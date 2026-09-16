rule TTP_XOR_QUAD_CurrentVersionRun_33d6 {
  strings:
    $key_33d6 = { 60 b9 [2] 44 b7 [2] 6f 9b [2] 41 b9 [2] 55 a2 [2] 5a b8 [2] 44 a5 [2] 46 a4 [2] 5d a2 [2] 41 a5 [2] 5d 8a }

  condition:
    any of them
}