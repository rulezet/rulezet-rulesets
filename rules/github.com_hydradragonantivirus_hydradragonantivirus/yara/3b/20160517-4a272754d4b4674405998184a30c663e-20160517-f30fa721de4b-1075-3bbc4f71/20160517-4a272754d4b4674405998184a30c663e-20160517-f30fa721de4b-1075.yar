rule _20160517_4a272754d4b4674405998184a30c663e_20160517_f30fa721de4b_1075 {
  meta:
    description = "datamaliciousorder - from files 20160517_4a272754d4b4674405998184a30c663e.js, 20160517_f30fa721de4bcc703f52a84ae1b66dcc.js, 20160517_fad6b1f3a13906cc3a729da27fdf0c77.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76d5e601509691fc105fda5d4ab37e889817255a3697b5b64f6ac77808a3a416"
    hash2       = "f1cf2b741154ad6251fd5c51a362842f928f28afa4387659d1510b9df66a7ebb"
    hash3       = "e17d214caf438a32fe514b9fa0adf1e30c735d9ba071115b7a70305d2e8e9fb6"

  strings:
    $s1 = "var nConverts1 /* f  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* f  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* f  */;};" fullword ascii
    $s4 = "var enjoy1 /* f  */ = false;" fullword ascii
    $s5 = "could = /* f  */(/* f  */\"noitisop\").split(''/* f  */).reverse(/* f  */).join('');" fullword ascii
    $s6 = "enjoy1 /* f  */ /* f  */= true;/* f  */" fullword ascii
    $s7 = "batch =/* f  */ \"R\" + \"esponseB\"/* f  */ + \"ydo\".split('').reverse().join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}