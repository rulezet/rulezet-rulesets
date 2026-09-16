rule TTP_XOR_MULT_DOSStub_e75c {
  strings:
    $key_e75c = { b3 34 [2] c7 2c [2] 80 2e [2] c7 3f [2] 89 33 [2] 85 39 [2] 92 32 [2] 89 7c [2] b4 }

  condition:
    any of them
}