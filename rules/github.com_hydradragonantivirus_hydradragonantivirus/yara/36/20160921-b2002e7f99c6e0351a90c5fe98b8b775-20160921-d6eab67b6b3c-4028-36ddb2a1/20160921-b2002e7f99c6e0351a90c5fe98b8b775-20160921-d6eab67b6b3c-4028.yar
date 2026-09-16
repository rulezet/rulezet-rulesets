rule _20160921_b2002e7f99c6e0351a90c5fe98b8b775_20160921_d6eab67b6b3c_4028 {
  meta:
    description = "datamaliciousorder - from files 20160921_b2002e7f99c6e0351a90c5fe98b8b775.js, 20160921_d6eab67b6b3cec2e5f5426840b084b70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e6376c7075a97cbb4e180ac5ea89ade4f5170dd182e1014b19fd2ed4aa33345"
    hash2       = "0ae44892f78e5b5ddfc07e6a23fb55469f21e12c45e74661ad81e61b07893ece"

  strings:
    $s1 = "return \"MDb\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Qj\";})()" ascii
    $s2 = ")(),(function f000(){return \"MDb\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Mc\";})(),(function f000" ascii
    $s3 = "urn \"Do\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Oh\";})(),(fu" ascii
    $s4 = "on f000(){return \"XTn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return " ascii
    $s5 = "(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Do\";}" ascii
    $s6 = "b\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"BQb\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}