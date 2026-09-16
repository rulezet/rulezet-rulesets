rule TTP_XOR_QUAD_CurrentVersionRun_4f5a {
  strings:
    $key_4f5a = { 1c 35 [2] 38 3b [2] 13 17 [2] 3d 35 [2] 29 2e [2] 26 34 [2] 38 29 [2] 3a 28 [2] 21 2e [2] 3d 29 [2] 21 06 }

  condition:
    any of them
}