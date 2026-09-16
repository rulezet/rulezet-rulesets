rule TTP_XOR_MULT_DOSStub_f464 {
  strings:
    $key_f464 = { a0 0c [2] d4 14 [2] 93 16 [2] d4 07 [2] 9a 0b [2] 96 01 [2] 81 0a [2] 9a 44 [2] a7 }

  condition:
    any of them
}