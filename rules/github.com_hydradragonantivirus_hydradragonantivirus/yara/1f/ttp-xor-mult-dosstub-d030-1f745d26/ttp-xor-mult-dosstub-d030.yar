rule TTP_XOR_MULT_DOSStub_d030 {
  strings:
    $key_d030 = { 84 58 [2] f0 40 [2] b7 42 [2] f0 53 [2] be 5f [2] b2 55 [2] a5 5e [2] be 10 [2] 83 }

  condition:
    any of them
}