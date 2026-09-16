rule TTP_XOR_QUAD_CurrentVersionRun_6c65 {
  strings:
    $key_6c65 = { 3f 0a [2] 1b 04 [2] 30 28 [2] 1e 0a [2] 0a 11 [2] 05 0b [2] 1b 16 [2] 19 17 [2] 02 11 [2] 1e 16 [2] 02 39 }

  condition:
    any of them
}