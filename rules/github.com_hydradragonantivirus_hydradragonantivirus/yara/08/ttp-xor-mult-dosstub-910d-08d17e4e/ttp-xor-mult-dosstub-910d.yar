rule TTP_XOR_MULT_DOSStub_910d {
  strings:
    $key_910d = { c5 65 [2] b1 7d [2] f6 7f [2] b1 6e [2] ff 62 [2] f3 68 [2] e4 63 [2] ff 2d [2] c2 }

  condition:
    any of them
}