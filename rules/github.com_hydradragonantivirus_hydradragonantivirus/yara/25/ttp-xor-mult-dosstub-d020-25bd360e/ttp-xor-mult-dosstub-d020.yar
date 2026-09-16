rule TTP_XOR_MULT_DOSStub_d020 {
  strings:
    $key_d020 = { 84 48 [2] f0 50 [2] b7 52 [2] f0 43 [2] be 4f [2] b2 45 [2] a5 4e [2] be 00 [2] 83 }

  condition:
    any of them
}