rule TTP_XOR_QUAD_CurrentVersionRun_3a18 {
  strings:
    $key_3a18 = { 69 77 [2] 4d 79 [2] 66 55 [2] 48 77 [2] 5c 6c [2] 53 76 [2] 4d 6b [2] 4f 6a [2] 54 6c [2] 48 6b [2] 54 44 }

  condition:
    any of them
}