rule CrowdStrike_blackpos_memscanner

{

    meta:

        description = "Tool Responsible for Scanning Memory For CC Data."

        last_modified = "2014-01-16"

        version = "1.0"

        in_the_wild = true

        copyright = "CrowdStrike, Inc"
        
        reference = "https://www.crowdstrike.com/blog/actionable-indicators-detection-signs-compromise-target-related-breaches/"


    strings:

        $message1 = "S region:"

        $message2 = " found ["

        $message3 = "] bytes of pattern:["

        $message4 = "CC2 region:"

        $message5 = "CC memregion:"

        $message6 = "KAPTOXA"

        $message7 = "=== pid:"

        $message8 = "scan process with pid for kartoxa and string pattern:"

        $message9 = "scan process with pid for kartoxa:"

        $message11 = "scan all processes for string pattern:"

    condition:

        2 of ($message*)

}