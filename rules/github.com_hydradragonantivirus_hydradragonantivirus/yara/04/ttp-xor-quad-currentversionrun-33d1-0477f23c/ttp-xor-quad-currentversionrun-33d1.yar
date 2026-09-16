rule TTP_XOR_QUAD_CurrentVersionRun_33d1 {
  strings:
    $key_33d1 = { 60 be [2] 44 b0 [2] 6f 9c [2] 41 be [2] 55 a5 [2] 5a bf [2] 44 a2 [2] 46 a3 [2] 5d a5 [2] 41 a2 [2] 5d 8d }

  condition:
    any of them
}