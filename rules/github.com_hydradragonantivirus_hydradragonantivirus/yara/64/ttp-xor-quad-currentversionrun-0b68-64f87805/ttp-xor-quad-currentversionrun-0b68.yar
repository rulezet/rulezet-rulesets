rule TTP_XOR_QUAD_CurrentVersionRun_0b68 {
  strings:
    $key_0b68 = { 58 07 [2] 7c 09 [2] 57 25 [2] 79 07 [2] 6d 1c [2] 62 06 [2] 7c 1b [2] 7e 1a [2] 65 1c [2] 79 1b [2] 65 34 }

  condition:
    any of them
}