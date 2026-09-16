rule TTP_XOR_QUAD_CurrentVersionRun_5739 {
  strings:
    $key_5739 = { 04 56 [2] 20 58 [2] 0b 74 [2] 25 56 [2] 31 4d [2] 3e 57 [2] 20 4a [2] 22 4b [2] 39 4d [2] 25 4a [2] 39 65 }

  condition:
    any of them
}