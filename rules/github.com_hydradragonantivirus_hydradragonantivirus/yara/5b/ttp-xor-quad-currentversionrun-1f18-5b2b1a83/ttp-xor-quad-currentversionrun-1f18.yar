rule TTP_XOR_QUAD_CurrentVersionRun_1f18 {
  strings:
    $key_1f18 = { 4c 77 [2] 68 79 [2] 43 55 [2] 6d 77 [2] 79 6c [2] 76 76 [2] 68 6b [2] 6a 6a [2] 71 6c [2] 6d 6b [2] 71 44 }

  condition:
    any of them
}