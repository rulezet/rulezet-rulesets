rule TTP_XOR_MULT_DOSStub_913d {
  strings:
    $key_913d = { c5 55 [2] b1 4d [2] f6 4f [2] b1 5e [2] ff 52 [2] f3 58 [2] e4 53 [2] ff 1d [2] c2 }

  condition:
    any of them
}