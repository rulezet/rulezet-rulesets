rule TTP_XOR_QUAD_CurrentVersionRun_6e50 {
  strings:
    $key_6e50 = { 3d 3f [2] 19 31 [2] 32 1d [2] 1c 3f [2] 08 24 [2] 07 3e [2] 19 23 [2] 1b 22 [2] 00 24 [2] 1c 23 [2] 00 0c }

  condition:
    any of them
}