rule TTP_XOR_MULT_DOSStub_d58e {
  strings:
    $key_d58e = { 81 e6 [2] f5 fe [2] b2 fc [2] f5 ed [2] bb e1 [2] b7 eb [2] a0 e0 [2] bb ae [2] 86 }

  condition:
    any of them
}