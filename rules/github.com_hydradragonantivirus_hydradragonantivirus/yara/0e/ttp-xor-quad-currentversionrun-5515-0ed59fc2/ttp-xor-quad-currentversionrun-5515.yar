rule TTP_XOR_QUAD_CurrentVersionRun_5515 {
  strings:
    $key_5515 = { 06 7a [2] 22 74 [2] 09 58 [2] 27 7a [2] 33 61 [2] 3c 7b [2] 22 66 [2] 20 67 [2] 3b 61 [2] 27 66 [2] 3b 49 }

  condition:
    any of them
}