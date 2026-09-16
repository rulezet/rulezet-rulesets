rule TTP_XOR_QUAD_CurrentVersionRun_6c45 {
  strings:
    $key_6c45 = { 3f 2a [2] 1b 24 [2] 30 08 [2] 1e 2a [2] 0a 31 [2] 05 2b [2] 1b 36 [2] 19 37 [2] 02 31 [2] 1e 36 [2] 02 19 }

  condition:
    any of them
}