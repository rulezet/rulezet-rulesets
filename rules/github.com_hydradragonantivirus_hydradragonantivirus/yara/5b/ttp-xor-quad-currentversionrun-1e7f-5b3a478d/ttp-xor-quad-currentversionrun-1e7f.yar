rule TTP_XOR_QUAD_CurrentVersionRun_1e7f {
  strings:
    $key_1e7f = { 4d 10 [2] 69 1e [2] 42 32 [2] 6c 10 [2] 78 0b [2] 77 11 [2] 69 0c [2] 6b 0d [2] 70 0b [2] 6c 0c [2] 70 23 }

  condition:
    any of them
}