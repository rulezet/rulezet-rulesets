rule TTP_XOR_QUAD_CurrentVersionRun_3c44 {
  strings:
    $key_3c44 = { 6f 2b [2] 4b 25 [2] 60 09 [2] 4e 2b [2] 5a 30 [2] 55 2a [2] 4b 37 [2] 49 36 [2] 52 30 [2] 4e 37 [2] 52 18 }

  condition:
    any of them
}