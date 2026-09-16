rule TTP_XOR_QUAD_CurrentVersionRun_7c38 {
  strings:
    $key_7c38 = { 2f 57 [2] 0b 59 [2] 20 75 [2] 0e 57 [2] 1a 4c [2] 15 56 [2] 0b 4b [2] 09 4a [2] 12 4c [2] 0e 4b [2] 12 64 }

  condition:
    any of them
}