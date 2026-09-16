rule _20160921_72cf8bebbcf48b45894fe7d7b3327a58_20160921_d47b4a8df439_3905 {
  meta:
    description = "datamaliciousorder - from files 20160921_72cf8bebbcf48b45894fe7d7b3327a58.js, 20160921_d47b4a8df4397da0f8d93fe0d9eeb14b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "004799df77a97e1e1816f6a4a1acf9bec5dfd13ae07613832796a6c9ef0cc578"
    hash2       = "78db1c7c22d3adc33c9ba580ac46df953d36c9c15f9c8b211dc68c16595dc18d"

  strings:
    $s1 = "eturn \"Qa\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(" ascii
    $s2 = "return \"OUx\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Wy\";})()" ascii
    $s3 = ")(),(function f000(){return \"Yv\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s4 = "\"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mt\";})(),(func" ascii
    $s5 = "urn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"MBb\";})()," ascii
    $s6 = "n f000(){return \"NBs\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}