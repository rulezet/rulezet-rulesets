rule TTP_XOR_QUAD_CurrentVersionRun_0845 {
  strings:
    $key_0845 = { 5b 2a [2] 7f 24 [2] 54 08 [2] 7a 2a [2] 6e 31 [2] 61 2b [2] 7f 36 [2] 7d 37 [2] 66 31 [2] 7a 36 [2] 66 19 }

  condition:
    any of them
}