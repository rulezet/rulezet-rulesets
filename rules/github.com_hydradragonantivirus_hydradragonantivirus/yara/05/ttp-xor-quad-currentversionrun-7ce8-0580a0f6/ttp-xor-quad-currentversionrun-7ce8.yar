rule TTP_XOR_QUAD_CurrentVersionRun_7ce8 {
  strings:
    $key_7ce8 = { 2f 87 [2] 0b 89 [2] 20 a5 [2] 0e 87 [2] 1a 9c [2] 15 86 [2] 0b 9b [2] 09 9a [2] 12 9c [2] 0e 9b [2] 12 b4 }

  condition:
    any of them
}