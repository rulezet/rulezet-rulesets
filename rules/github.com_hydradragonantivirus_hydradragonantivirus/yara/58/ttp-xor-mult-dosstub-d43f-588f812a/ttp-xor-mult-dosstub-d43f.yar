rule TTP_XOR_MULT_DOSStub_d43f {
  strings:
    $key_d43f = { 80 57 [2] f4 4f [2] b3 4d [2] f4 5c [2] ba 50 [2] b6 5a [2] a1 51 [2] ba 1f [2] 87 }

  condition:
    any of them
}