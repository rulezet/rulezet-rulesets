rule TTP_XOR_QUAD_CurrentVersionRun_1e2f {
  strings:
    $key_1e2f = { 4d 40 [2] 69 4e [2] 42 62 [2] 6c 40 [2] 78 5b [2] 77 41 [2] 69 5c [2] 6b 5d [2] 70 5b [2] 6c 5c [2] 70 73 }

  condition:
    any of them
}