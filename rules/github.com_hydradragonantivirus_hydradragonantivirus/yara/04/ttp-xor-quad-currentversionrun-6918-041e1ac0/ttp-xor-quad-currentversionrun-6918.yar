rule TTP_XOR_QUAD_CurrentVersionRun_6918 {
  strings:
    $key_6918 = { 3a 77 [2] 1e 79 [2] 35 55 [2] 1b 77 [2] 0f 6c [2] 00 76 [2] 1e 6b [2] 1c 6a [2] 07 6c [2] 1b 6b [2] 07 44 }

  condition:
    any of them
}