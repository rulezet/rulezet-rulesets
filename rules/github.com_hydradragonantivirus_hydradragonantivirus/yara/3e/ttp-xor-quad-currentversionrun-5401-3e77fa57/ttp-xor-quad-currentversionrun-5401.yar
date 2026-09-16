rule TTP_XOR_QUAD_CurrentVersionRun_5401 {
  strings:
    $key_5401 = { 07 6e [2] 23 60 [2] 08 4c [2] 26 6e [2] 32 75 [2] 3d 6f [2] 23 72 [2] 21 73 [2] 3a 75 [2] 26 72 [2] 3a 5d }

  condition:
    any of them
}