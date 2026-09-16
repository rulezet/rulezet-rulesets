rule TTP_XOR_QUAD_CurrentVersionRun_485a {
  strings:
    $key_485a = { 1b 35 [2] 3f 3b [2] 14 17 [2] 3a 35 [2] 2e 2e [2] 21 34 [2] 3f 29 [2] 3d 28 [2] 26 2e [2] 3a 29 [2] 26 06 }

  condition:
    any of them
}