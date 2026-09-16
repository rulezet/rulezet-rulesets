rule _20160921_2c106cc001daa2dffdfde7e2aa5c908b_20160921_b1a0d856c15e_4812 {
  meta:
    description = "datamaliciousorder - from files 20160921_2c106cc001daa2dffdfde7e2aa5c908b.js, 20160921_b1a0d856c15e8cb36e6ba699332db942.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca5356b92abf859d45d843749f45e5e06c7d045b4e7ea5d215ab87cdb8c8f66b"
    hash2       = "88dbe0c95aef9105f735a6441467700856e7377cc24ac1dbd7d9bcd256b0aa29"

  strings:
    $s1 = "nction fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){retu" ascii
    $s2 = "ck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Ve\";" ascii
    $s3 = "ck(){return \"We\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\"" ascii
    $s4 = "n fuck(){return \"USf\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return " ascii
    $s5 = "{return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}