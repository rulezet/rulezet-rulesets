rule TTP_XOR_QUAD_CurrentVersionRun_6e7d {
  strings:
    $key_6e7d = { 3d 12 [2] 19 1c [2] 32 30 [2] 1c 12 [2] 08 09 [2] 07 13 [2] 19 0e [2] 1b 0f [2] 00 09 [2] 1c 0e [2] 00 21 }

  condition:
    any of them
}