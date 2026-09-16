rule SUSP_References_Likely_Traffic_Capture_eth0
{
    meta:
        author = "Greg Lesnewich"
        description = "look for string refs to eth0 that might get used for traffic capture"
        date = "2024-02-11"
        version = "1.0"
        DaysOfYARA = "41/100"
        reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"

    strings:
        $  = "eth0" nocase ascii wide
    condition:
        1 of them
}