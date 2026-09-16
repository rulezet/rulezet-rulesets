rule TTP_XOR_QUAD_CurrentVersionRun_1e2e {
  strings:
    $key_1e2e = { 4d 41 [2] 69 4f [2] 42 63 [2] 6c 41 [2] 78 5a [2] 77 40 [2] 69 5d [2] 6b 5c [2] 70 5a [2] 6c 5d [2] 70 72 }

  condition:
    any of them
}