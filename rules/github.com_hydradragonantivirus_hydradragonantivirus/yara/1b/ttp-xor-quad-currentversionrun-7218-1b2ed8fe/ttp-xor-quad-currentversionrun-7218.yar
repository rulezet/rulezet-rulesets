rule TTP_XOR_QUAD_CurrentVersionRun_7218 {
  strings:
    $key_7218 = { 21 77 [2] 05 79 [2] 2e 55 [2] 00 77 [2] 14 6c [2] 1b 76 [2] 05 6b [2] 07 6a [2] 1c 6c [2] 00 6b [2] 1c 44 }

  condition:
    any of them
}