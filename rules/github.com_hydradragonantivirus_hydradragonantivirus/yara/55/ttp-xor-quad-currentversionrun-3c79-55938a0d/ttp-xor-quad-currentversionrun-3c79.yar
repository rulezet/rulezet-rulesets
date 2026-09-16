rule TTP_XOR_QUAD_CurrentVersionRun_3c79 {
  strings:
    $key_3c79 = { 6f 16 [2] 4b 18 [2] 60 34 [2] 4e 16 [2] 5a 0d [2] 55 17 [2] 4b 0a [2] 49 0b [2] 52 0d [2] 4e 0a [2] 52 25 }

  condition:
    any of them
}