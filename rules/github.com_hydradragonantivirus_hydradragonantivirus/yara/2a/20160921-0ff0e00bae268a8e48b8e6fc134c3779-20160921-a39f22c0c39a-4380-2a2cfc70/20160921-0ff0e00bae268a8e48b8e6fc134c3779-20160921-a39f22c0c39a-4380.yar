rule _20160921_0ff0e00bae268a8e48b8e6fc134c3779_20160921_a39f22c0c39a_4380 {
  meta:
    description = "datamaliciousorder - from files 20160921_0ff0e00bae268a8e48b8e6fc134c3779.js, 20160921_a39f22c0c39a7d5bb3c55dd00a36b5b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f9f30b45066ff23899a854b2ef766240b2becea05223ad11c6bf5cde97c3048"
    hash2       = "6a56bdeaf1decad9c4fa4ee5ac7e377d80dfd12601d1317d02f12d9d9fb19646"

  strings:
    $s1 = "n f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"SEo\";})(),(function f000(){return " ascii
    $s2 = ")(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000()" ascii
    $s3 = "rn \"Lo\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"DNa\";})(),(f" ascii
    $s4 = "f000(){return \"Tn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"GG" ascii
    $s5 = ",(function f000(){return \"Fs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}