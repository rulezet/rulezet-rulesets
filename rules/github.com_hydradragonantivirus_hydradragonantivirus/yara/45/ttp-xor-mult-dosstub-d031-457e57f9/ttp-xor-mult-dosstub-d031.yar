rule TTP_XOR_MULT_DOSStub_d031 {
  strings:
    $key_d031 = { 84 59 [2] f0 41 [2] b7 43 [2] f0 52 [2] be 5e [2] b2 54 [2] a5 5f [2] be 11 [2] 83 }

  condition:
    any of them
}