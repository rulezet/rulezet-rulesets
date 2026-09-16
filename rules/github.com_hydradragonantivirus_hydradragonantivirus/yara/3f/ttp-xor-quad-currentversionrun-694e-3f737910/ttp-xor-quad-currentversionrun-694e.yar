rule TTP_XOR_QUAD_CurrentVersionRun_694e {
  strings:
    $key_694e = { 3a 21 [2] 1e 2f [2] 35 03 [2] 1b 21 [2] 0f 3a [2] 00 20 [2] 1e 3d [2] 1c 3c [2] 07 3a [2] 1b 3d [2] 07 12 }

  condition:
    any of them
}