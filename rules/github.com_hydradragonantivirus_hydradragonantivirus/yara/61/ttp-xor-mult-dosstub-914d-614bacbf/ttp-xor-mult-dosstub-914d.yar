rule TTP_XOR_MULT_DOSStub_914d {
  strings:
    $key_914d = { c5 25 [2] b1 3d [2] f6 3f [2] b1 2e [2] ff 22 [2] f3 28 [2] e4 23 [2] ff 6d [2] c2 }

  condition:
    any of them
}