rule TTP_XOR_MULT_DOSStub_672f {
  strings:
    $key_672f = { 33 47 [2] 47 5f [2] 00 5d [2] 47 4c [2] 09 40 [2] 05 4a [2] 12 41 [2] 09 0f [2] 34 }

  condition:
    any of them
}