rule TTP_XOR_MULT_DOSStub_d47a {
  strings:
    $key_d47a = { 80 12 [2] f4 0a [2] b3 08 [2] f4 19 [2] ba 15 [2] b6 1f [2] a1 14 [2] ba 5a [2] 87 }

  condition:
    any of them
}