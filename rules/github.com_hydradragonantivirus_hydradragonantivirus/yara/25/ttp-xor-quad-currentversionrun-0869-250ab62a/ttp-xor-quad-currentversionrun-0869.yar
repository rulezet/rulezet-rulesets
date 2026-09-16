rule TTP_XOR_QUAD_CurrentVersionRun_0869 {
  strings:
    $key_0869 = { 5b 06 [2] 7f 08 [2] 54 24 [2] 7a 06 [2] 6e 1d [2] 61 07 [2] 7f 1a [2] 7d 1b [2] 66 1d [2] 7a 1a [2] 66 35 }

  condition:
    any of them
}