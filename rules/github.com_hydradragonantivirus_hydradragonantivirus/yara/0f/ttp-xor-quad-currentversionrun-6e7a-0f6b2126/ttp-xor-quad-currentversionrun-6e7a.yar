rule TTP_XOR_QUAD_CurrentVersionRun_6e7a {
  strings:
    $key_6e7a = { 3d 15 [2] 19 1b [2] 32 37 [2] 1c 15 [2] 08 0e [2] 07 14 [2] 19 09 [2] 1b 08 [2] 00 0e [2] 1c 09 [2] 00 26 }

  condition:
    any of them
}