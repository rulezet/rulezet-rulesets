rule TTP_XOR_QUAD_CurrentVersionRun_36e5 {
  strings:
    $key_36e5 = { 65 8a [2] 41 84 [2] 6a a8 [2] 44 8a [2] 50 91 [2] 5f 8b [2] 41 96 [2] 43 97 [2] 58 91 [2] 44 96 [2] 58 b9 }

  condition:
    any of them
}