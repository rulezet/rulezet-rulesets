rule TTP_XOR_MULT_DOSStub_923d {
  strings:
    $key_923d = { c6 55 [2] b2 4d [2] f5 4f [2] b2 5e [2] fc 52 [2] f0 58 [2] e7 53 [2] fc 1d [2] c1 }

  condition:
    any of them
}