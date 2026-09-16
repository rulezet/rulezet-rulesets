rule _20160921_c1ad71fea9bd3e371590c0c373f087a1_20160921_d1c97b87a698_4053 {
  meta:
    description = "datamaliciousorder - from files 20160921_c1ad71fea9bd3e371590c0c373f087a1.js, 20160921_d1c97b87a6985071e0e4edfb0e0dcc81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf0e0decfb5414f48e1bcf494a6c63e6249e9ac1433d4fba6a461b5970957194"
    hash2       = "b5d1f1d63107b329353fe8130c80608d28a9b1ed12f81c240129d04be6842bf0"

  strings:
    $s1 = "ction f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"KDh\";})(),(function f000(){retu" ascii
    $s2 = "ction f000(){return \"Wb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s3 = "urn \"SEo\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(" ascii
    $s4 = "return \"Wb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(" ascii
    $s5 = "ction f000(){return \"TRc\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return" ascii
    $s6 = "){return \"Yi\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}