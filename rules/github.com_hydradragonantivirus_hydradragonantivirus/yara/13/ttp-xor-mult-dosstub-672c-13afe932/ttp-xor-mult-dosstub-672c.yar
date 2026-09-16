rule TTP_XOR_MULT_DOSStub_672c {
  strings:
    $key_672c = { 33 44 [2] 47 5c [2] 00 5e [2] 47 4f [2] 09 43 [2] 05 49 [2] 12 42 [2] 09 0c [2] 34 }

  condition:
    any of them
}