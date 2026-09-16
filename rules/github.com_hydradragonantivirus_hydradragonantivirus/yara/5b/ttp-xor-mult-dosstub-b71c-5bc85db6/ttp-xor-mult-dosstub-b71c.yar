rule TTP_XOR_MULT_DOSStub_b71c {
  strings:
    $key_b71c = { e3 74 [2] 97 6c [2] d0 6e [2] 97 7f [2] d9 73 [2] d5 79 [2] c2 72 [2] d9 3c [2] e4 }

  condition:
    any of them
}