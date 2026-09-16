rule TTP_XOR_QUAD_CurrentVersionRun_00ed {
  strings:
    $key_00ed = { 53 82 [2] 77 8c [2] 5c a0 [2] 72 82 [2] 66 99 [2] 69 83 [2] 77 9e [2] 75 9f [2] 6e 99 [2] 72 9e [2] 6e b1 }

  condition:
    any of them
}