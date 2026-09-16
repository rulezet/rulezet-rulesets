rule TTP_XOR_MULT_DOSStub_d4ba {
  strings:
    $key_d4ba = { 80 d2 [2] f4 ca [2] b3 c8 [2] f4 d9 [2] ba d5 [2] b6 df [2] a1 d4 [2] ba 9a [2] 87 }

  condition:
    any of them
}