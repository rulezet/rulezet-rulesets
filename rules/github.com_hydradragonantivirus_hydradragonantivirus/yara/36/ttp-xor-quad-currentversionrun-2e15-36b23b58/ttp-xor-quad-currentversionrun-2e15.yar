rule TTP_XOR_QUAD_CurrentVersionRun_2e15 {
  strings:
    $key_2e15 = { 7d 7a [2] 59 74 [2] 72 58 [2] 5c 7a [2] 48 61 [2] 47 7b [2] 59 66 [2] 5b 67 [2] 40 61 [2] 5c 66 [2] 40 49 }

  condition:
    any of them
}