rule _20160921_83dee40cf10de766ec203f9fab018b5c_20160921_95ced062e055_5461 {
  meta:
    description = "datamaliciousorder - from files 20160921_83dee40cf10de766ec203f9fab018b5c.js, 20160921_95ced062e0552048d29cf59daab852db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da20d9f2ad414b6bfc45df4fc34c3fc042e1740d759013b54b408f28740fef3f"
    hash2       = "62e6b62d08a320533bdb97151951141555c4f9ccf26ad306c0e21644b883ab60"

  strings:
    $s1 = "ction f000(){return \"ZGq\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"Wh\";})(),(function f000(){return" ascii
    $s2 = "eturn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Sq\";})()," ascii
    $s3 = "){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"MJq\";}" ascii
    $s4 = ",(function f000(){return \"ZGq\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s5 = "ZFe\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}