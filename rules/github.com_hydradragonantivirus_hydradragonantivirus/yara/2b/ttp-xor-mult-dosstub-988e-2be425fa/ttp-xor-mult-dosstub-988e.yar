rule TTP_XOR_MULT_DOSStub_988e {
  strings:
    $key_988e = { cc e6 [2] b8 fe [2] ff fc [2] b8 ed [2] f6 e1 [2] fa eb [2] ed e0 [2] f6 ae [2] cb }

  condition:
    any of them
}