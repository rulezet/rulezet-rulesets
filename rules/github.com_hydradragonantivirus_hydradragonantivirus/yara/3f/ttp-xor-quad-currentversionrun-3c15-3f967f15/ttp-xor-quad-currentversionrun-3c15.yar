rule TTP_XOR_QUAD_CurrentVersionRun_3c15 {
  strings:
    $key_3c15 = { 6f 7a [2] 4b 74 [2] 60 58 [2] 4e 7a [2] 5a 61 [2] 55 7b [2] 4b 66 [2] 49 67 [2] 52 61 [2] 4e 66 [2] 52 49 }

  condition:
    any of them
}