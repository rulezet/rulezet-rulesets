rule TTP_XOR_QUAD_CurrentVersionRun_2d2b {
  strings:
    $key_2d2b = { 7e 44 [2] 5a 4a [2] 71 66 [2] 5f 44 [2] 4b 5f [2] 44 45 [2] 5a 58 [2] 58 59 [2] 43 5f [2] 5f 58 [2] 43 77 }

  condition:
    any of them
}