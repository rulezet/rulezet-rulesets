rule TTP_XOR_QUAD_CurrentVersionRun_1a18 {
  strings:
    $key_1a18 = { 49 77 [2] 6d 79 [2] 46 55 [2] 68 77 [2] 7c 6c [2] 73 76 [2] 6d 6b [2] 6f 6a [2] 74 6c [2] 68 6b [2] 74 44 }

  condition:
    any of them
}