rule TTP_XOR_MULT_DOSStub_917d {
  strings:
    $key_917d = { c5 15 [2] b1 0d [2] f6 0f [2] b1 1e [2] ff 12 [2] f3 18 [2] e4 13 [2] ff 5d [2] c2 }

  condition:
    any of them
}