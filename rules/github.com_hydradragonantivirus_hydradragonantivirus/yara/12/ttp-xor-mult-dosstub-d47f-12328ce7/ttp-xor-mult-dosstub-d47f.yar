rule TTP_XOR_MULT_DOSStub_d47f {
  strings:
    $key_d47f = { 80 17 [2] f4 0f [2] b3 0d [2] f4 1c [2] ba 10 [2] b6 1a [2] a1 11 [2] ba 5f [2] 87 }

  condition:
    any of them
}