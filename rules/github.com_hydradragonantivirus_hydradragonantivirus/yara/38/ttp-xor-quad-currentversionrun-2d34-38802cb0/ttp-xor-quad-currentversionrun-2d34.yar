rule TTP_XOR_QUAD_CurrentVersionRun_2d34 {
  strings:
    $key_2d34 = { 7e 5b [2] 5a 55 [2] 71 79 [2] 5f 5b [2] 4b 40 [2] 44 5a [2] 5a 47 [2] 58 46 [2] 43 40 [2] 5f 47 [2] 43 68 }

  condition:
    any of them
}