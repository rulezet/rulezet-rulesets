rule TTP_XOR_QUAD_CurrentVersionRun_5331 {
  strings:
    $key_5331 = { 00 5e [2] 24 50 [2] 0f 7c [2] 21 5e [2] 35 45 [2] 3a 5f [2] 24 42 [2] 26 43 [2] 3d 45 [2] 21 42 [2] 3d 6d }

  condition:
    any of them
}