rule TTP_XOR_QUAD_CurrentVersionRun_78e5 {
  strings:
    $key_78e5 = { 2b 8a [2] 0f 84 [2] 24 a8 [2] 0a 8a [2] 1e 91 [2] 11 8b [2] 0f 96 [2] 0d 97 [2] 16 91 [2] 0a 96 [2] 16 b9 }

  condition:
    any of them
}