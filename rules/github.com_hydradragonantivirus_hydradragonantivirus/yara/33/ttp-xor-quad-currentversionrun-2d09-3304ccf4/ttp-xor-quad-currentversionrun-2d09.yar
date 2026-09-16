rule TTP_XOR_QUAD_CurrentVersionRun_2d09 {
  strings:
    $key_2d09 = { 7e 66 [2] 5a 68 [2] 71 44 [2] 5f 66 [2] 4b 7d [2] 44 67 [2] 5a 7a [2] 58 7b [2] 43 7d [2] 5f 7a [2] 43 55 }

  condition:
    any of them
}