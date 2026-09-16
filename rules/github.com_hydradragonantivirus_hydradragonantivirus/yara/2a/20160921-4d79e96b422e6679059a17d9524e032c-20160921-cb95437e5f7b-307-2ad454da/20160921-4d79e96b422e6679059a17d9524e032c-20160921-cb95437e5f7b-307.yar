rule _20160921_4d79e96b422e6679059a17d9524e032c_20160921_cb95437e5f7b_307 {
  meta:
    description = "datamaliciousorder - from files 20160921_4d79e96b422e6679059a17d9524e032c.js, 20160921_cb95437e5f7b0cd43bdbd6381ee6a105.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5794a16a28dba8e89768fa9195da33a7e28c3da5fc73a7789e7c04395f23f06"
    hash2       = "46d771acb80357bcbb0857af9e7a4a35304fdbbf9785ec02f88f92f1268dfa71"

  strings:
    $s1  = "n \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"USf\";})(),(fun" ascii
    $s2  = "{return \"Np\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"NKq\";})(" ascii
    $s3  = "function fuck(){return \"ADy\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){ret" ascii
    $s4  = "(function fuck(){return \"MBg\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){r" ascii
    $s5  = "eturn \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Cd\";})()," ascii
    $s6  = "nction fuck(){return \"PDf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){ret" ascii
    $s7  = "unction fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){ret" ascii
    $s8  = "on fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return " ascii
    $s9  = " fuck(){return \"Cd\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"I" ascii
    $s10 = "ion fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return " ascii
    $s11 = "ck(){return \"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"PDf" ascii
    $s12 = "\"PDf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(func" ascii
    $s13 = "k(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\"" ascii
    $s14 = " fuck(){return \"Ve\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Y" ascii
    $s15 = "\"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(fun" ascii
    $s16 = "urn \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})(),(f" ascii
    $s17 = "(){return \"IKv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"LGo\"" ascii
    $s18 = "\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Cd\";})(),(function " ascii
    $s19 = ")(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"GNm\";})(),(function fuc" ascii
    $s20 = "ck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Cd\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}