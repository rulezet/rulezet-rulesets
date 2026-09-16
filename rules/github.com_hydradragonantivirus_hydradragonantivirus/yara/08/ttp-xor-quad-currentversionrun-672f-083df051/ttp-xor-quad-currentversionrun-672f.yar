rule TTP_XOR_QUAD_CurrentVersionRun_672f {
  strings:
    $key_672f = { 34 40 [2] 10 4e [2] 3b 62 [2] 15 40 [2] 01 5b [2] 0e 41 [2] 10 5c [2] 12 5d [2] 09 5b [2] 15 5c [2] 09 73 }

  condition:
    any of them
}