rule TTP_XOR_QUAD_CurrentVersionRun_6715 {
  strings:
    $key_6715 = { 34 7a [2] 10 74 [2] 3b 58 [2] 15 7a [2] 01 61 [2] 0e 7b [2] 10 66 [2] 12 67 [2] 09 61 [2] 15 66 [2] 09 49 }

  condition:
    any of them
}