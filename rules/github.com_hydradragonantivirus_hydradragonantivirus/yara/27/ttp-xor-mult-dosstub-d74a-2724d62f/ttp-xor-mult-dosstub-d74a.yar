rule TTP_XOR_MULT_DOSStub_d74a {
  strings:
    $key_d74a = { 83 22 [2] f7 3a [2] b0 38 [2] f7 29 [2] b9 25 [2] b5 2f [2] a2 24 [2] b9 6a [2] 84 }

  condition:
    any of them
}