rule _20160921_0e1bfa63bcb2804e89834c330285643e_20160921_ad1fccc6910b_4368 {
  meta:
    description = "datamaliciousorder - from files 20160921_0e1bfa63bcb2804e89834c330285643e.js, 20160921_ad1fccc6910bd9c4a47aa9bd3e9239da.js, 20160921_d0ae6acc5cc4f52f8d5df0b47ef8659a.js, 20160921_e39622eeb1da8fbbf03ca86989251a47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d58b57cb825244d35e22402fcf08c9ababcc51eb72a7913c47dbb2143171df32"
    hash2       = "a49fc1cb85eaa58b7c63197e9fd25224f63dcb6c86b906933f698898634ead3e"
    hash3       = "8cde265a6a44d9e9f86f351959c030a86800d101b5b5ca057ac1cdc5c5a1e38d"
    hash4       = "e0b1660f1c95284f1a0f8062a1f16e26aa3d58e3fa4cf47fc04824d02b754a56"

  strings:
    $s1 = "tion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){retur" ascii
    $s2 = "b\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Jo\";})(),(function" ascii
    $s3 = "nction fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){ret" ascii
    $s4 = "return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})()" ascii
    $s5 = "{return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}