rule TTP_XOR_QUAD_CurrentVersionRun_7814 {
  strings:
    $key_7814 = { 2b 7b [2] 0f 75 [2] 24 59 [2] 0a 7b [2] 1e 60 [2] 11 7a [2] 0f 67 [2] 0d 66 [2] 16 60 [2] 0a 67 [2] 16 48 }

  condition:
    any of them
}