rule TTP_XOR_QUAD_CurrentVersionRun_2545 {
  strings:
    $key_2545 = { 76 2a [2] 52 24 [2] 79 08 [2] 57 2a [2] 43 31 [2] 4c 2b [2] 52 36 [2] 50 37 [2] 4b 31 [2] 57 36 [2] 4b 19 }

  condition:
    any of them
}