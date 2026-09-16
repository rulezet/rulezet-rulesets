rule TTP_XOR_QUAD_CurrentVersionRun_5018 {
  strings:
    $key_5018 = { 03 77 [2] 27 79 [2] 0c 55 [2] 22 77 [2] 36 6c [2] 39 76 [2] 27 6b [2] 25 6a [2] 3e 6c [2] 22 6b [2] 3e 44 }

  condition:
    any of them
}