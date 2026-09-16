rule INDICATOR_KB_GoBuildID_GoldenAxe {
    meta:
        author = "ditekSHen"
        description = "Detects Golang Build IDs in known bad samples"       
    strings:
        $s1 = "Go build ID: \"BrJuyMRdiZ7pC9Cah0is/rbDB__hXWimivbSGiCLi/B35SPLQwHal3ccR2gXNx/hEmVzhJWWatsrKwnENh_\"" ascii
        $s2 = "Go build ID: \"5bgieaBe9PcZCZf23WFp/bCZ0AUHYlqQmX8GJASV6/fGxRLMDDYrTm1jcLMt8j/Wof3n5634bwiwLHFKHTn\"" ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 8000KB and 1 of them
}