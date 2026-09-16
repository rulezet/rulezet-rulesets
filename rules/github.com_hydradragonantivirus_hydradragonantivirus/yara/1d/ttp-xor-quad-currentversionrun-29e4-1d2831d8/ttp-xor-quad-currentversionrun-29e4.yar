rule TTP_XOR_QUAD_CurrentVersionRun_29e4 {
  strings:
    $key_29e4 = { 7a 8b [2] 5e 85 [2] 75 a9 [2] 5b 8b [2] 4f 90 [2] 40 8a [2] 5e 97 [2] 5c 96 [2] 47 90 [2] 5b 97 [2] 47 b8 }

  condition:
    any of them
}