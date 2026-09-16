rule TTP_XOR_MULT_DOSStub_d00c {
  strings:
    $key_d00c = { 84 64 [2] f0 7c [2] b7 7e [2] f0 6f [2] be 63 [2] b2 69 [2] a5 62 [2] be 2c [2] 83 }

  condition:
    any of them
}