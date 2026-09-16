rule TTP_XOR_QUAD_CurrentVersionRun_6c17 {
  strings:
    $key_6c17 = { 3f 78 [2] 1b 76 [2] 30 5a [2] 1e 78 [2] 0a 63 [2] 05 79 [2] 1b 64 [2] 19 65 [2] 02 63 [2] 1e 64 [2] 02 4b }

  condition:
    any of them
}