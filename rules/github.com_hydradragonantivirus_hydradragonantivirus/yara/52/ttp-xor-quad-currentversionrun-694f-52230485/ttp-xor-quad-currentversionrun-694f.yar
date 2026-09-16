rule TTP_XOR_QUAD_CurrentVersionRun_694f {
  strings:
    $key_694f = { 3a 20 [2] 1e 2e [2] 35 02 [2] 1b 20 [2] 0f 3b [2] 00 21 [2] 1e 3c [2] 1c 3d [2] 07 3b [2] 1b 3c [2] 07 13 }

  condition:
    any of them
}