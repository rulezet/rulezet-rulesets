rule TTP_XOR_MULT_DOSStub_d906 {
  strings:
    $key_d906 = { 8d 6e [2] f9 76 [2] be 74 [2] f9 65 [2] b7 69 [2] bb 63 [2] ac 68 [2] b7 26 [2] 8a }

  condition:
    any of them
}