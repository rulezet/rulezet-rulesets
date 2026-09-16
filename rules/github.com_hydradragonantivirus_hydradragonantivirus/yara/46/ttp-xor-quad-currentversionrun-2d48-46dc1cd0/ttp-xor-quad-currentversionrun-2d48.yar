rule TTP_XOR_QUAD_CurrentVersionRun_2d48 {
  strings:
    $key_2d48 = { 7e 27 [2] 5a 29 [2] 71 05 [2] 5f 27 [2] 4b 3c [2] 44 26 [2] 5a 3b [2] 58 3a [2] 43 3c [2] 5f 3b [2] 43 14 }

  condition:
    any of them
}