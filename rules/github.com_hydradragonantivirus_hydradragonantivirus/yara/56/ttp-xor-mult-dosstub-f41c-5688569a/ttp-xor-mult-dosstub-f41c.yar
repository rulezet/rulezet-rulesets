rule TTP_XOR_MULT_DOSStub_f41c {
  strings:
    $key_f41c = { a0 74 [2] d4 6c [2] 93 6e [2] d4 7f [2] 9a 73 [2] 96 79 [2] 81 72 [2] 9a 3c [2] a7 }

  condition:
    any of them
}