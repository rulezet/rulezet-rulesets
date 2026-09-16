rule TTP_XOR_QUAD_CurrentVersionRun_3965 {
  strings:
    $key_3965 = { 6a 0a [2] 4e 04 [2] 65 28 [2] 4b 0a [2] 5f 11 [2] 50 0b [2] 4e 16 [2] 4c 17 [2] 57 11 [2] 4b 16 [2] 57 39 }

  condition:
    any of them
}