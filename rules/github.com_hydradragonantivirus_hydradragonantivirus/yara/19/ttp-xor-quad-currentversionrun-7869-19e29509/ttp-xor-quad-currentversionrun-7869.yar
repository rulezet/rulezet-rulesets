rule TTP_XOR_QUAD_CurrentVersionRun_7869 {
  strings:
    $key_7869 = { 2b 06 [2] 0f 08 [2] 24 24 [2] 0a 06 [2] 1e 1d [2] 11 07 [2] 0f 1a [2] 0d 1b [2] 16 1d [2] 0a 1a [2] 16 35 }

  condition:
    any of them
}