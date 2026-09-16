rule Remcos_audio_recording
{
    meta:
        description = "Detects Remcos audio recording capability."
        
    strings:
        $api1 = "waveInOpen" ascii
        $api2 = "waveInStart" ascii
        
    condition:
        uint16(0) == 0x5A4D and all of them
}