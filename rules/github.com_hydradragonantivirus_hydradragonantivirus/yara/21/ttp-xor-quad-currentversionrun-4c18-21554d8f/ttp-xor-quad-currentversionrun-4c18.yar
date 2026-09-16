rule TTP_XOR_QUAD_CurrentVersionRun_4c18 {
  strings:
    $key_4c18 = { 1f 77 [2] 3b 79 [2] 10 55 [2] 3e 77 [2] 2a 6c [2] 25 76 [2] 3b 6b [2] 39 6a [2] 22 6c [2] 3e 6b [2] 22 44 }

  condition:
    any of them
}