rule TTP_XOR_MULT_DOSStub_989d {
  strings:
    $key_989d = { cc f5 [2] b8 ed [2] ff ef [2] b8 fe [2] f6 f2 [2] fa f8 [2] ed f3 [2] f6 bd [2] cb }

  condition:
    any of them
}