rule TTP_XOR_QUAD_CurrentVersionRun_2d15 {
  strings:
    $key_2d15 = { 7e 7a [2] 5a 74 [2] 71 58 [2] 5f 7a [2] 4b 61 [2] 44 7b [2] 5a 66 [2] 58 67 [2] 43 61 [2] 5f 66 [2] 43 49 }

  condition:
    any of them
}