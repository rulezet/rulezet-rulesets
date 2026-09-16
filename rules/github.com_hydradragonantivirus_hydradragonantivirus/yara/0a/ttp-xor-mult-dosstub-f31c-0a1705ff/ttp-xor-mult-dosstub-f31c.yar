rule TTP_XOR_MULT_DOSStub_f31c {
  strings:
    $key_f31c = { a7 74 [2] d3 6c [2] 94 6e [2] d3 7f [2] 9d 73 [2] 91 79 [2] 86 72 [2] 9d 3c [2] a0 }

  condition:
    any of them
}