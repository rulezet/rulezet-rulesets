rule TTP_XOR_QUAD_CurrentVersionRun_3855 {
  strings:
    $key_3855 = { 6b 3a [2] 4f 34 [2] 64 18 [2] 4a 3a [2] 5e 21 [2] 51 3b [2] 4f 26 [2] 4d 27 [2] 56 21 [2] 4a 26 [2] 56 09 }

  condition:
    any of them
}