rule TTP_XOR_MULT_DOSStub_d75c {
  strings:
    $key_d75c = { 83 34 [2] f7 2c [2] b0 2e [2] f7 3f [2] b9 33 [2] b5 39 [2] a2 32 [2] b9 7c [2] 84 }

  condition:
    any of them
}