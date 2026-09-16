rule TTP_XOR_QUAD_CurrentVersionRun_2d05 {
  strings:
    $key_2d05 = { 7e 6a [2] 5a 64 [2] 71 48 [2] 5f 6a [2] 4b 71 [2] 44 6b [2] 5a 76 [2] 58 77 [2] 43 71 [2] 5f 76 [2] 43 59 }

  condition:
    any of them
}