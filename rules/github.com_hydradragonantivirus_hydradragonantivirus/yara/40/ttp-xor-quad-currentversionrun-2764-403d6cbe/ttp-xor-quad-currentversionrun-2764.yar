rule TTP_XOR_QUAD_CurrentVersionRun_2764 {
  strings:
    $key_2764 = { 74 0b [2] 50 05 [2] 7b 29 [2] 55 0b [2] 41 10 [2] 4e 0a [2] 50 17 [2] 52 16 [2] 49 10 [2] 55 17 [2] 49 38 }

  condition:
    any of them
}