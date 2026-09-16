rule TTP_XOR_QUAD_CurrentVersionRun_3579 {
  strings:
    $key_3579 = { 66 16 [2] 42 18 [2] 69 34 [2] 47 16 [2] 53 0d [2] 5c 17 [2] 42 0a [2] 40 0b [2] 5b 0d [2] 47 0a [2] 5b 25 }

  condition:
    any of them
}