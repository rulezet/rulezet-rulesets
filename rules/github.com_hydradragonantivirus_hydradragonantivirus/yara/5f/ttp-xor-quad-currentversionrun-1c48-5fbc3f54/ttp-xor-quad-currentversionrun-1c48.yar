rule TTP_XOR_QUAD_CurrentVersionRun_1c48 {
  strings:
    $key_1c48 = { 4f 27 [2] 6b 29 [2] 40 05 [2] 6e 27 [2] 7a 3c [2] 75 26 [2] 6b 3b [2] 69 3a [2] 72 3c [2] 6e 3b [2] 72 14 }

  condition:
    any of them
}