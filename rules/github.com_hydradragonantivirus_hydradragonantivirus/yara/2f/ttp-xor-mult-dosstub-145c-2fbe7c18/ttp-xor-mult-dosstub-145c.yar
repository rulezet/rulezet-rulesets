rule TTP_XOR_MULT_DOSStub_145c {
  strings:
    $key_145c = { 40 34 [2] 34 2c [2] 73 2e [2] 34 3f [2] 7a 33 [2] 76 39 [2] 61 32 [2] 7a 7c [2] 47 }

  condition:
    any of them
}