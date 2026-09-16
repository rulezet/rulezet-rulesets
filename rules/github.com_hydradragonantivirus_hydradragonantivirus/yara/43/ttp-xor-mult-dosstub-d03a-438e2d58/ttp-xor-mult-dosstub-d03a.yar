rule TTP_XOR_MULT_DOSStub_d03a {
  strings:
    $key_d03a = { 84 52 [2] f0 4a [2] b7 48 [2] f0 59 [2] be 55 [2] b2 5f [2] a5 54 [2] be 1a [2] 83 }

  condition:
    any of them
}