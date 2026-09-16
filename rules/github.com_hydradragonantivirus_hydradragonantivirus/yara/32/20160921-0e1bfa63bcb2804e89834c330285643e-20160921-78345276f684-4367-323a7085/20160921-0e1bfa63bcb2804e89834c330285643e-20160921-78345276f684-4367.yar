rule _20160921_0e1bfa63bcb2804e89834c330285643e_20160921_78345276f684_4367 {
  meta:
    description = "datamaliciousorder - from files 20160921_0e1bfa63bcb2804e89834c330285643e.js, 20160921_78345276f684d53628bbcac810994182.js, 20160921_ad1fccc6910bd9c4a47aa9bd3e9239da.js, 20160921_e39622eeb1da8fbbf03ca86989251a47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d58b57cb825244d35e22402fcf08c9ababcc51eb72a7913c47dbb2143171df32"
    hash2       = "17b203684b4f2284de883c81e8fef63ea03c36bd0599ccb85d3175be35d9ac6d"
    hash3       = "a49fc1cb85eaa58b7c63197e9fd25224f63dcb6c86b906933f698898634ead3e"
    hash4       = "e0b1660f1c95284f1a0f8062a1f16e26aa3d58e3fa4cf47fc04824d02b754a56"

  strings:
    $s1 = "\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"IRn\";})(),(function f" ascii
    $s2 = "ction fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){retu" ascii
    $s3 = "on fuck(){return \"Et\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s4 = "\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Et\";})(),(function fu" ascii
    $s5 = "function fuck(){return \"Et\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Et\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}