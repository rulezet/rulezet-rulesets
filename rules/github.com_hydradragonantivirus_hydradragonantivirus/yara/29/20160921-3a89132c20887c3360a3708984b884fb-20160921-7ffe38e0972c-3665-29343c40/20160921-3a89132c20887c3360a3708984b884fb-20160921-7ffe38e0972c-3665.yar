rule _20160921_3a89132c20887c3360a3708984b884fb_20160921_7ffe38e0972c_3665 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a89132c20887c3360a3708984b884fb.js, 20160921_7ffe38e0972c323071684bfa98cafbdf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9687ad9b2ded14e00c5b17393de82acd451266863fb217fc6647e1add112f2fd"
    hash2       = "4bc751383d4c72f88b3f59d9fde1f38f09a81b77ee4df0498bec1df7cd088bc7"

  strings:
    $s1 = "eturn \"UOt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})()" ascii
    $s2 = "unction f000(){return \"IAa\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKl\";})(),(function f000(){ret" ascii
    $s3 = "00(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vu" ascii
    $s4 = "turn \"BMj\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(" ascii
    $s5 = "on f000(){return \"Zj\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"M" ascii
    $s6 = "nction f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}