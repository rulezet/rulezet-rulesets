rule TTP_XOR_MULT_DOSStub_d75a {
  strings:
    $key_d75a = { 83 32 [2] f7 2a [2] b0 28 [2] f7 39 [2] b9 35 [2] b5 3f [2] a2 34 [2] b9 7a [2] 84 }

  condition:
    any of them
}