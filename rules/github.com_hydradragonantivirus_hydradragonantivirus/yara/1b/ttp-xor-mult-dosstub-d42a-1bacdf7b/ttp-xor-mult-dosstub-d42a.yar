rule TTP_XOR_MULT_DOSStub_d42a {
  strings:
    $key_d42a = { 80 42 [2] f4 5a [2] b3 58 [2] f4 49 [2] ba 45 [2] b6 4f [2] a1 44 [2] ba 0a [2] 87 }

  condition:
    any of them
}