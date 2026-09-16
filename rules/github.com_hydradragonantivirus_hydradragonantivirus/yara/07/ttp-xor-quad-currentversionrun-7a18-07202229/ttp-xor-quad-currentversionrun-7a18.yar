rule TTP_XOR_QUAD_CurrentVersionRun_7a18 {
  strings:
    $key_7a18 = { 29 77 [2] 0d 79 [2] 26 55 [2] 08 77 [2] 1c 6c [2] 13 76 [2] 0d 6b [2] 0f 6a [2] 14 6c [2] 08 6b [2] 14 44 }

  condition:
    any of them
}