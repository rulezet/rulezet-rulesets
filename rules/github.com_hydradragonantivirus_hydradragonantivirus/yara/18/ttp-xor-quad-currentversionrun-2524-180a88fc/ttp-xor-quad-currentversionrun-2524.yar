rule TTP_XOR_QUAD_CurrentVersionRun_2524 {
  strings:
    $key_2524 = { 76 4b [2] 52 45 [2] 79 69 [2] 57 4b [2] 43 50 [2] 4c 4a [2] 52 57 [2] 50 56 [2] 4b 50 [2] 57 57 [2] 4b 78 }

  condition:
    any of them
}