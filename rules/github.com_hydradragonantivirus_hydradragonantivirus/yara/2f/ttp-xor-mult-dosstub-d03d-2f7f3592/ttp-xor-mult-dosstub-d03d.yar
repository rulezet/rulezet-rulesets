rule TTP_XOR_MULT_DOSStub_d03d {
  strings:
    $key_d03d = { 84 55 [2] f0 4d [2] b7 4f [2] f0 5e [2] be 52 [2] b2 58 [2] a5 53 [2] be 1d [2] 83 }

  condition:
    any of them
}