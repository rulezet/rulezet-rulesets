rule _20160921_b1a0d856c15e8cb36e6ba699332db942_20160921_b23a0d871d76_3124 {
  meta:
    description = "datamaliciousorder - from files 20160921_b1a0d856c15e8cb36e6ba699332db942.js, 20160921_b23a0d871d76c64a3c71f0b0f52faaa8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88dbe0c95aef9105f735a6441467700856e7377cc24ac1dbd7d9bcd256b0aa29"
    hash2       = "02969139df11550b994530c0bcbc6d946b6e49105015e9475f5de3942d78e5a1"

  strings:
    $s1 = "return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"IOs\";})" ascii
    $s2 = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Fv\";})(),(function fuck()" ascii
    $s3 = " \"Hs\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(func" ascii
    $s4 = "tion fuck(){return \"To\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return " ascii
    $s5 = "g\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function " ascii
    $s6 = "fuck(){return \"Zy\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"IR" ascii
    $s7 = "turn \"YAv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}