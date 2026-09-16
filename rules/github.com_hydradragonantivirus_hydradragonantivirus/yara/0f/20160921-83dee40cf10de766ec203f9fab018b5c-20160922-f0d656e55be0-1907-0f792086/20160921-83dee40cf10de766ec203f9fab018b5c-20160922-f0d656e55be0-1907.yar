rule _20160921_83dee40cf10de766ec203f9fab018b5c_20160922_f0d656e55be0_1907 {
  meta:
    description = "datamaliciousorder - from files 20160921_83dee40cf10de766ec203f9fab018b5c.js, 20160922_f0d656e55be0c93b2b5e1f0eda45da9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da20d9f2ad414b6bfc45df4fc34c3fc042e1740d759013b54b408f28740fef3f"
    hash2       = "276c24e399a13bf7907294578800d75620fb48bcd34bc84b9d92448375c72d37"

  strings:
    $s1  = "ction f000(){return \"YTp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s2  = "turn \"PTs\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Kw\";})(),(" ascii
    $s3  = "(){return \"ZGq\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";}" ascii
    $s4  = "n f000(){return \"Mc\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"" ascii
    $s5  = "{return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"RLk\";}" ascii
    $s6  = "0(){return \"MJq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Sv\"" ascii
    $s7  = "\"Rh\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"RLk\";})(),(func" ascii
    $s8  = "Na\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"MDb\";})(),(functi" ascii
    $s9  = "p\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s10 = "unction f000(){return \"MJq\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}