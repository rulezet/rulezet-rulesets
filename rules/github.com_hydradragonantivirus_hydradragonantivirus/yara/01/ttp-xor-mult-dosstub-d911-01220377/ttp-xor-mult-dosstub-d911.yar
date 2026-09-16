rule TTP_XOR_MULT_DOSStub_d911 {
  strings:
    $key_d911 = { 8d 79 [2] f9 61 [2] be 63 [2] f9 72 [2] b7 7e [2] bb 74 [2] ac 7f [2] b7 31 [2] 8a }

  condition:
    any of them
}