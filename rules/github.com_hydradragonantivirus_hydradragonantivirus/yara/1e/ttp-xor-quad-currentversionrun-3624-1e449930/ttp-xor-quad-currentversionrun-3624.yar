rule TTP_XOR_QUAD_CurrentVersionRun_3624 {
  strings:
    $key_3624 = { 65 4b [2] 41 45 [2] 6a 69 [2] 44 4b [2] 50 50 [2] 5f 4a [2] 41 57 [2] 43 56 [2] 58 50 [2] 44 57 [2] 58 78 }

  condition:
    any of them
}