import "pe"
rule ms15_093_plugx_dll_payload : APT malware
{
    meta:
        author = "rnolen@bit9.com"
        date = "8.26.2015"
        description = "Find a specific plugx variant DLL payload"
        hash1 = "20d88b0fa34d3d79629cb602f08a1145008a75215fe2c91a3b3171287adc4c3d"
    strings:
        $datfile = "nvdisps_user.dat"
        $dllfile = "nvdisps.dll"
        $mutex    = "nvdisps_event"
    condition:
        3 of ($datfile,$dllfile,$mutex) and pe.exports("ShadowPlay")
}