rule TTP_XOR_QUAD_CurrentVersionRun_6c0b {
  strings:
    $key_6c0b = { 3f 64 [2] 1b 6a [2] 30 46 [2] 1e 64 [2] 0a 7f [2] 05 65 [2] 1b 78 [2] 19 79 [2] 02 7f [2] 1e 78 [2] 02 57 }

  condition:
    any of them
}