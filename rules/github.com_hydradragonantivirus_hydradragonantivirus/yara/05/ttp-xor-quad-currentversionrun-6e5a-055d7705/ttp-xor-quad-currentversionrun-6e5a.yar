rule TTP_XOR_QUAD_CurrentVersionRun_6e5a {
  strings:
    $key_6e5a = { 3d 35 [2] 19 3b [2] 32 17 [2] 1c 35 [2] 08 2e [2] 07 34 [2] 19 29 [2] 1b 28 [2] 00 2e [2] 1c 29 [2] 00 06 }

  condition:
    any of them
}