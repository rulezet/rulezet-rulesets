rule TTP_XOR_QUAD_CurrentVersionRun_7c18 {
  strings:
    $key_7c18 = { 2f 77 [2] 0b 79 [2] 20 55 [2] 0e 77 [2] 1a 6c [2] 15 76 [2] 0b 6b [2] 09 6a [2] 12 6c [2] 0e 6b [2] 12 44 }

  condition:
    any of them
}