rule TTP_XOR_QUAD_CurrentVersionRun_5779 {
  strings:
    $key_5779 = { 04 16 [2] 20 18 [2] 0b 34 [2] 25 16 [2] 31 0d [2] 3e 17 [2] 20 0a [2] 22 0b [2] 39 0d [2] 25 0a [2] 39 25 }

  condition:
    any of them
}