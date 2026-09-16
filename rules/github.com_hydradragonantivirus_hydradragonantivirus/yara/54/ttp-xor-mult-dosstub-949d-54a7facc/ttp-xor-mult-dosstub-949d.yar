rule TTP_XOR_MULT_DOSStub_949d {
  strings:
    $key_949d = { c0 f5 [2] b4 ed [2] f3 ef [2] b4 fe [2] fa f2 [2] f6 f8 [2] e1 f3 [2] fa bd [2] c7 }

  condition:
    any of them
}