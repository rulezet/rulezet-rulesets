rule TTP_XOR_MULT_DOSStub_d46f {
  strings:
    $key_d46f = { 80 07 [2] f4 1f [2] b3 1d [2] f4 0c [2] ba 00 [2] b6 0a [2] a1 01 [2] ba 4f [2] 87 }

  condition:
    any of them
}