rule TTP_XOR_QUAD_CurrentVersionRun_1918 {
  strings:
    $key_1918 = { 4a 77 [2] 6e 79 [2] 45 55 [2] 6b 77 [2] 7f 6c [2] 70 76 [2] 6e 6b [2] 6c 6a [2] 77 6c [2] 6b 6b [2] 77 44 }

  condition:
    any of them
}