rule TTP_XOR_MULT_DOSStub_989b {
  strings:
    $key_989b = { cc f3 [2] b8 eb [2] ff e9 [2] b8 f8 [2] f6 f4 [2] fa fe [2] ed f5 [2] f6 bb [2] cb }

  condition:
    any of them
}