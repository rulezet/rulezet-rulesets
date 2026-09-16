rule TTP_XOR_MULT_DOSStub_e15c {
  strings:
    $key_e15c = { b5 34 [2] c1 2c [2] 86 2e [2] c1 3f [2] 8f 33 [2] 83 39 [2] 94 32 [2] 8f 7c [2] b2 }

  condition:
    any of them
}