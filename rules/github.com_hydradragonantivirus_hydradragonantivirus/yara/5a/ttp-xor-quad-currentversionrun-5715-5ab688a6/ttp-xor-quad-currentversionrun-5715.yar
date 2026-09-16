rule TTP_XOR_QUAD_CurrentVersionRun_5715 {
  strings:
    $key_5715 = { 04 7a [2] 20 74 [2] 0b 58 [2] 25 7a [2] 31 61 [2] 3e 7b [2] 20 66 [2] 22 67 [2] 39 61 [2] 25 66 [2] 39 49 }

  condition:
    any of them
}