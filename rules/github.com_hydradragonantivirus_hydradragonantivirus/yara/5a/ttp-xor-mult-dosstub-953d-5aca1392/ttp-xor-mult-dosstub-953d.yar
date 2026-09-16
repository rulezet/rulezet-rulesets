rule TTP_XOR_MULT_DOSStub_953d {
  strings:
    $key_953d = { c1 55 [2] b5 4d [2] f2 4f [2] b5 5e [2] fb 52 [2] f7 58 [2] e0 53 [2] fb 1d [2] c6 }

  condition:
    any of them
}