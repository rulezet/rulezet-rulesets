rule TTP_XOR_QUAD_CurrentVersionRun_2745 {
  strings:
    $key_2745 = { 74 2a [2] 50 24 [2] 7b 08 [2] 55 2a [2] 41 31 [2] 4e 2b [2] 50 36 [2] 52 37 [2] 49 31 [2] 55 36 [2] 49 19 }

  condition:
    any of them
}