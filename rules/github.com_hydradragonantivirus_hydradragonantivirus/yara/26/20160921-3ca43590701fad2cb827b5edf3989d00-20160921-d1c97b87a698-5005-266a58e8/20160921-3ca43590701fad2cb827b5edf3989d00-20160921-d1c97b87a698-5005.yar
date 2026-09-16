rule _20160921_3ca43590701fad2cb827b5edf3989d00_20160921_d1c97b87a698_5005 {
  meta:
    description = "datamaliciousorder - from files 20160921_3ca43590701fad2cb827b5edf3989d00.js, 20160921_d1c97b87a6985071e0e4edfb0e0dcc81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef7c5701a8646e7803463e9a01e4f2e45cd535f2ed7174e97abde991a779b665"
    hash2       = "b5d1f1d63107b329353fe8130c80608d28a9b1ed12f81c240129d04be6842bf0"

  strings:
    $s1 = "ction f000(){return \"ZIi\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"MDb\";})(),(function f000(){retur" ascii
    $s2 = "function f000(){return \"Vj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s3 = "(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(" ascii
    $s4 = "f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vu" ascii
    $s5 = "rn \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}