rule TTP_XOR_QUAD_CurrentVersionRun_0008 {
  strings:
    $key_0008 = { 53 67 [2] 77 69 [2] 5c 45 [2] 72 67 [2] 66 7c [2] 69 66 [2] 77 7b [2] 75 7a [2] 6e 7c [2] 72 7b [2] 6e 54 }

  condition:
    any of them
}