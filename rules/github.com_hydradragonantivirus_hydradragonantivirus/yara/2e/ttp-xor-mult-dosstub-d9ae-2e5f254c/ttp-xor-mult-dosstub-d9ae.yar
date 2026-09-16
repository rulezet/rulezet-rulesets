rule TTP_XOR_MULT_DOSStub_d9ae {
  strings:
    $key_d9ae = { 8d c6 [2] f9 de [2] be dc [2] f9 cd [2] b7 c1 [2] bb cb [2] ac c0 [2] b7 8e [2] 8a }

  condition:
    any of them
}