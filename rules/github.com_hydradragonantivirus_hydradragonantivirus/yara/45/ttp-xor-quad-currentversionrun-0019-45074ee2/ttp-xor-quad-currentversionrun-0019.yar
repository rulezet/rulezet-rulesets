rule TTP_XOR_QUAD_CurrentVersionRun_0019 {
  strings:
    $key_0019 = { 53 76 [2] 77 78 [2] 5c 54 [2] 72 76 [2] 66 6d [2] 69 77 [2] 77 6a [2] 75 6b [2] 6e 6d [2] 72 6a [2] 6e 45 }

  condition:
    any of them
}