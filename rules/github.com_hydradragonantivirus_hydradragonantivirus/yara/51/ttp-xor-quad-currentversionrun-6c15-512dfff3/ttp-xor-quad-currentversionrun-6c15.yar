rule TTP_XOR_QUAD_CurrentVersionRun_6c15 {
  strings:
    $key_6c15 = { 3f 7a [2] 1b 74 [2] 30 58 [2] 1e 7a [2] 0a 61 [2] 05 7b [2] 1b 66 [2] 19 67 [2] 02 61 [2] 1e 66 [2] 02 49 }

  condition:
    any of them
}