rule TTP_XOR_QUAD_CurrentVersionRun_0018 {
  strings:
    $key_0018 = { 53 77 [2] 77 79 [2] 5c 55 [2] 72 77 [2] 66 6c [2] 69 76 [2] 77 6b [2] 75 6a [2] 6e 6c [2] 72 6b [2] 6e 44 }

  condition:
    any of them
}