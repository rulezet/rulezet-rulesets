rule TTP_XOR_QUAD_CurrentVersionRun_6eea {
  strings:
    $key_6eea = { 3d 85 [2] 19 8b [2] 32 a7 [2] 1c 85 [2] 08 9e [2] 07 84 [2] 19 99 [2] 1b 98 [2] 00 9e [2] 1c 99 [2] 00 b6 }

  condition:
    any of them
}