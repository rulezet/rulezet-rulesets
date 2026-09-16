rule TTP_XOR_QUAD_CurrentVersionRun_3964 {
  strings:
    $key_3964 = { 6a 0b [2] 4e 05 [2] 65 29 [2] 4b 0b [2] 5f 10 [2] 50 0a [2] 4e 17 [2] 4c 16 [2] 57 10 [2] 4b 17 [2] 57 38 }

  condition:
    any of them
}