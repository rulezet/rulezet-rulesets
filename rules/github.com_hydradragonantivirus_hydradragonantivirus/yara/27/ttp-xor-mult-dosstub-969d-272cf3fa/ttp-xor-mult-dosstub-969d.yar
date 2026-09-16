rule TTP_XOR_MULT_DOSStub_969d {
  strings:
    $key_969d = { c2 f5 [2] b6 ed [2] f1 ef [2] b6 fe [2] f8 f2 [2] f4 f8 [2] e3 f3 [2] f8 bd [2] c5 }

  condition:
    any of them
}