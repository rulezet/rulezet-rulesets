rule TTP_XOR_MULT_DOSStub_d45c {
  strings:
    $key_d45c = { 80 34 [2] f4 2c [2] b3 2e [2] f4 3f [2] ba 33 [2] b6 39 [2] a1 32 [2] ba 7c [2] 87 }

  condition:
    any of them
}