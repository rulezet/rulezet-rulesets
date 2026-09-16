rule TTP_XOR_QUAD_CurrentVersionRun_0118 {
  strings:
    $key_0118 = { 52 77 [2] 76 79 [2] 5d 55 [2] 73 77 [2] 67 6c [2] 68 76 [2] 76 6b [2] 74 6a [2] 6f 6c [2] 73 6b [2] 6f 44 }

  condition:
    any of them
}