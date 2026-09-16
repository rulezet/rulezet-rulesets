rule TTP_XOR_QUAD_CurrentVersionRun_6d18 {
  strings:
    $key_6d18 = { 3e 77 [2] 1a 79 [2] 31 55 [2] 1f 77 [2] 0b 6c [2] 04 76 [2] 1a 6b [2] 18 6a [2] 03 6c [2] 1f 6b [2] 03 44 }

  condition:
    any of them
}