rule TTP_XOR_QUAD_CurrentVersionRun_5320 {
  strings:
    $key_5320 = { 00 4f [2] 24 41 [2] 0f 6d [2] 21 4f [2] 35 54 [2] 3a 4e [2] 24 53 [2] 26 52 [2] 3d 54 [2] 21 53 [2] 3d 7c }

  condition:
    any of them
}