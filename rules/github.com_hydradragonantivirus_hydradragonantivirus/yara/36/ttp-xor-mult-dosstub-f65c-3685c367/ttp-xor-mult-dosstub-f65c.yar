rule TTP_XOR_MULT_DOSStub_f65c {
  strings:
    $key_f65c = { a2 34 [2] d6 2c [2] 91 2e [2] d6 3f [2] 98 33 [2] 94 39 [2] 83 32 [2] 98 7c [2] a5 }

  condition:
    any of them
}