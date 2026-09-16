rule TTP_XOR_QUAD_CurrentVersionRun_6c18 {
  strings:
    $key_6c18 = { 3f 77 [2] 1b 79 [2] 30 55 [2] 1e 77 [2] 0a 6c [2] 05 76 [2] 1b 6b [2] 19 6a [2] 02 6c [2] 1e 6b [2] 02 44 }

  condition:
    any of them
}