rule TTP_XOR_QUAD_CurrentVersionRun_5312 {
  strings:
    $key_5312 = { 00 7d [2] 24 73 [2] 0f 5f [2] 21 7d [2] 35 66 [2] 3a 7c [2] 24 61 [2] 26 60 [2] 3d 66 [2] 21 61 [2] 3d 4e }

  condition:
    any of them
}