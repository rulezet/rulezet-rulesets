rule TTP_XOR_QUAD_CurrentVersionRun_672e {
  strings:
    $key_672e = { 34 41 [2] 10 4f [2] 3b 63 [2] 15 41 [2] 01 5a [2] 0e 40 [2] 10 5d [2] 12 5c [2] 09 5a [2] 15 5d [2] 09 72 }

  condition:
    any of them
}