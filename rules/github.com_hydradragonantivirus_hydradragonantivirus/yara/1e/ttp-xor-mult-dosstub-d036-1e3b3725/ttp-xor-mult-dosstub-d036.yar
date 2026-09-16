rule TTP_XOR_MULT_DOSStub_d036 {
  strings:
    $key_d036 = { 84 5e [2] f0 46 [2] b7 44 [2] f0 55 [2] be 59 [2] b2 53 [2] a5 58 [2] be 16 [2] 83 }

  condition:
    any of them
}