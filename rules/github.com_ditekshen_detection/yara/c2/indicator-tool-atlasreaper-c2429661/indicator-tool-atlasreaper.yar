rule INDICATOR_TOOL_AtlasReaper {
    meta:
        author = "ditekSHen"
        description = "Detects AtlasReaper command-line tool for Confluence and Jira reconnaissance, credential farming and social engineering"
    strings:
        $s1 = "/((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})/" fullword wide
        $s2 = "/rest/api/3/search?jql=" fullword wide
        $s3 = "attachments+IS+NOT+EMPTY&fields=attachment,summary,status" fullword wide
        $s4 = "<ParseJira>b__" ascii
        $s5 = "<Atlas_Doc_Format>k__" ascii
        $s6 = "<ParseConfluence>b__" ascii
        $s7 = "AtlasReaper_ProcessedByFody" fullword ascii
        $s8 = /AtlasReaper\.(Jira|Confluence)/ fullword ascii
    condition:
        uint16(0) == 0x5a4d and 4 of them
}