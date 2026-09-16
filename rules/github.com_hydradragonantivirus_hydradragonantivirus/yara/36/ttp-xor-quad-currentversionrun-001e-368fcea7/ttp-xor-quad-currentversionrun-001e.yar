rule TTP_XOR_QUAD_CurrentVersionRun_001e {
  strings:
    $key_001e = { 53 71 [2] 77 7f [2] 5c 53 [2] 72 71 [2] 66 6a [2] 69 70 [2] 77 6d [2] 75 6c [2] 6e 6a [2] 72 6d [2] 6e 42 }

  condition:
    any of them
}