rule TTP_XOR_QUAD_CurrentVersionRun_6c78 {
  strings:
    $key_6c78 = { 3f 17 [2] 1b 19 [2] 30 35 [2] 1e 17 [2] 0a 0c [2] 05 16 [2] 1b 0b [2] 19 0a [2] 02 0c [2] 1e 0b [2] 02 24 }

  condition:
    any of them
}