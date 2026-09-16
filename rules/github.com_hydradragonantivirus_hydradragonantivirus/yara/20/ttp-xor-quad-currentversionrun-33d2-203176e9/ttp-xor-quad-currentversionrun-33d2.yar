rule TTP_XOR_QUAD_CurrentVersionRun_33d2 {
  strings:
    $key_33d2 = { 60 bd [2] 44 b3 [2] 6f 9f [2] 41 bd [2] 55 a6 [2] 5a bc [2] 44 a1 [2] 46 a0 [2] 5d a6 [2] 41 a1 [2] 5d 8e }

  condition:
    any of them
}