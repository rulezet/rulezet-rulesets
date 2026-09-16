rule TTP_XOR_MULT_DOSStub_e45c {
  strings:
    $key_e45c = { b0 34 [2] c4 2c [2] 83 2e [2] c4 3f [2] 8a 33 [2] 86 39 [2] 91 32 [2] 8a 7c [2] b7 }

  condition:
    any of them
}