rule Remcos_version_agent_breakingsecurity_strings
{
    meta:
        description = "Detects Remcos RAT version, agent and BreakingSecurity strings."
        
    strings:
        $v1 = "Remcos v" ascii wide
        $v2 = /\d+\.\d+\.\d+ Pro/ ascii wide
        $v3 = "Remcos Agent" ascii wide
        $v4 = "BreakingSecurity.net" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and 2 of them
}