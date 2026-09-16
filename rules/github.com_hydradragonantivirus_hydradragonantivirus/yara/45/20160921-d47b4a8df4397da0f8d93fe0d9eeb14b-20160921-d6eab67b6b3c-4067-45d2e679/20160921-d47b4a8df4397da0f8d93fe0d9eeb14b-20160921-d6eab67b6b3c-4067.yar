rule _20160921_d47b4a8df4397da0f8d93fe0d9eeb14b_20160921_d6eab67b6b3c_4067 {
  meta:
    description = "datamaliciousorder - from files 20160921_d47b4a8df4397da0f8d93fe0d9eeb14b.js, 20160921_d6eab67b6b3cec2e5f5426840b084b70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78db1c7c22d3adc33c9ba580ac46df953d36c9c15f9c8b211dc68c16595dc18d"
    hash2       = "0ae44892f78e5b5ddfc07e6a23fb55469f21e12c45e74661ad81e61b07893ece"

  strings:
    $s1 = "ction f000(){return \"Km\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Wy\";})(),(function f000(){return " ascii
    $s2 = "(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mt\";})(),(function f000(){r" ascii
    $s3 = "Gn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"RVb\";})(),(functio" ascii
    $s4 = " \"Vj\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(func" ascii
    $s5 = "000(){return \"RLk\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii
    $s6 = "Gn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKl\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}