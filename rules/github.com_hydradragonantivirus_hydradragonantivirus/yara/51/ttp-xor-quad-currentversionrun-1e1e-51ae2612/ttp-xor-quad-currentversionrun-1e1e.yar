rule TTP_XOR_QUAD_CurrentVersionRun_1e1e {
  strings:
    $key_1e1e = { 4d 71 [2] 69 7f [2] 42 53 [2] 6c 71 [2] 78 6a [2] 77 70 [2] 69 6d [2] 6b 6c [2] 70 6a [2] 6c 6d [2] 70 42 }

  condition:
    any of them
}