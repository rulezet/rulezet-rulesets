rule TTP_XOR_QUAD_CurrentVersionRun_5725 {
  strings:
    $key_5725 = { 04 4a [2] 20 44 [2] 0b 68 [2] 25 4a [2] 31 51 [2] 3e 4b [2] 20 56 [2] 22 57 [2] 39 51 [2] 25 56 [2] 39 79 }

  condition:
    any of them
}