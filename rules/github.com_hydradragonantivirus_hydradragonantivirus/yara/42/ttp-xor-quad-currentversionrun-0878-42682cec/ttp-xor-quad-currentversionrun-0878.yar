rule TTP_XOR_QUAD_CurrentVersionRun_0878 {
  strings:
    $key_0878 = { 5b 17 [2] 7f 19 [2] 54 35 [2] 7a 17 [2] 6e 0c [2] 61 16 [2] 7f 0b [2] 7d 0a [2] 66 0c [2] 7a 0b [2] 66 24 }

  condition:
    any of them
}