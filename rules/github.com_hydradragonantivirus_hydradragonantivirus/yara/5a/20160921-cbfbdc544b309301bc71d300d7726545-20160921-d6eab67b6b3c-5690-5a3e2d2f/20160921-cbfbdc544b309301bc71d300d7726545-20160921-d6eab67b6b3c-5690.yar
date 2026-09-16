rule _20160921_cbfbdc544b309301bc71d300d7726545_20160921_d6eab67b6b3c_5690 {
  meta:
    description = "datamaliciousorder - from files 20160921_cbfbdc544b309301bc71d300d7726545.js, 20160921_d6eab67b6b3cec2e5f5426840b084b70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "135f44db2fcd47db2f5b9cd01f10f5c892ae119d904f5cb0ea4bbdaafba92963"
    hash2       = "0ae44892f78e5b5ddfc07e6a23fb55469f21e12c45e74661ad81e61b07893ece"

  strings:
    $s1 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"UEg\";})(),(function f00" ascii
    $s2 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Sq\";})(),(function f00" ascii
    $s3 = "unction f000(){return \"WIj\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000(){retu" ascii
    $s4 = "on f000(){return \"SEo\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s5 = ";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";})(),(function f0" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}