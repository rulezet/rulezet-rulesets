rule TTP_XOR_MULT_DOSStub_f14c {
  strings:
    $key_f14c = { a5 24 [2] d1 3c [2] 96 3e [2] d1 2f [2] 9f 23 [2] 93 29 [2] 84 22 [2] 9f 6c [2] a2 }

  condition:
    any of them
}