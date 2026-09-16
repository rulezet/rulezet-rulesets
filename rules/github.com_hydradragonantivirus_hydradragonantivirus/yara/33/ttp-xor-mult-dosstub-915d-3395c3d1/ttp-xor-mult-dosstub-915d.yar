rule TTP_XOR_MULT_DOSStub_915d {
  strings:
    $key_915d = { c5 35 [2] b1 2d [2] f6 2f [2] b1 3e [2] ff 32 [2] f3 38 [2] e4 33 [2] ff 7d [2] c2 }

  condition:
    any of them
}