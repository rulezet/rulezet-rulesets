rule TTP_XOR_QUAD_CurrentVersionRun_3279 {
  strings:
    $key_3279 = { 61 16 [2] 45 18 [2] 6e 34 [2] 40 16 [2] 54 0d [2] 5b 17 [2] 45 0a [2] 47 0b [2] 5c 0d [2] 40 0a [2] 5c 25 }

  condition:
    any of them
}