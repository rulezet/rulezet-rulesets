rule TTP_XOR_MULT_DOSStub_672d {
  strings:
    $key_672d = { 33 45 [2] 47 5d [2] 00 5f [2] 47 4e [2] 09 42 [2] 05 48 [2] 12 43 [2] 09 0d [2] 34 }

  condition:
    any of them
}