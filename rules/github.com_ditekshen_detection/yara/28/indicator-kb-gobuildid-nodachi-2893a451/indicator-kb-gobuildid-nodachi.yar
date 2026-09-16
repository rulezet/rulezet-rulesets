rule INDICATOR_KB_GoBuildID_Nodachi {
    meta:
        author = "ditekSHen"
        description = "Detects Golang Build IDs in Nodachi"       
    strings:
        $s1 = "Go build ID: \"3AAyhKK0wFfCYLdz5oRV/zKyiBHCsAEyDIWhaW5AW/Rb8NLT3q8A2OLm6izDGP/8G9k_gjOTX_PXKna_IMj\"" ascii
        $s2 = "Go build ID: \"-eyFd8kbpwxUsutpqZn_/vqzQXX5Ra4qk1XHoqocW/wd-6gLzQKZyEyhVp7qOj/Jr14hyc7pLLgeIZNbfLD\"" ascii
        $s3 = "Go build ID: \"xDSqp4KGmd0SAf5irMGh/-kA7PGjKoJcvCgsZDStn/lHeQ1LQOVyQB2NnwIwFP/-D5oEBc23ND7IGLTESdM\"" ascii
        $s4 = "Go build ID: \"67RcwNspLH__QJrElMcB/zMJf7Go1s0ZoXqd30Lb_/NaJl4rfcuLEG5LeZ-Y4k/MzFNvW79enRRdx3LmA47\"" ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}