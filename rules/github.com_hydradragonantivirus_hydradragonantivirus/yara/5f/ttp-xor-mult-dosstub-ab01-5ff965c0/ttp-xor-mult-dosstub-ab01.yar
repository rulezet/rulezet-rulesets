rule TTP_XOR_MULT_DOSStub_ab01 {
  strings:
    $key_ab01 = { ff 69 [2] 8b 71 [2] cc 73 [2] 8b 62 [2] c5 6e [2] c9 64 [2] de 6f [2] c5 21 [2] f8 }

  condition:
    any of them
}