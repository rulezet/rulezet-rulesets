rule TTP_XOR_QUAD_CurrentVersionRun_7d4e {
  strings:
    $key_7d4e = { 2e 21 [2] 0a 2f [2] 21 03 [2] 0f 21 [2] 1b 3a [2] 14 20 [2] 0a 3d [2] 08 3c [2] 13 3a [2] 0f 3d [2] 13 12 }

  condition:
    any of them
}