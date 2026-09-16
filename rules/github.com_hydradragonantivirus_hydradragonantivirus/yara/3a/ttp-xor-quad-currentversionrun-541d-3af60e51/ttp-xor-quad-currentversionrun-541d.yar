rule TTP_XOR_QUAD_CurrentVersionRun_541d {
  strings:
    $key_541d = { 07 72 [2] 23 7c [2] 08 50 [2] 26 72 [2] 32 69 [2] 3d 73 [2] 23 6e [2] 21 6f [2] 3a 69 [2] 26 6e [2] 3a 41 }

  condition:
    any of them
}