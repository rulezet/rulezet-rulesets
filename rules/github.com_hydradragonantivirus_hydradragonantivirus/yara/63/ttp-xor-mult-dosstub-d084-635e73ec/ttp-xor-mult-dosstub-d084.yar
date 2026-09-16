rule TTP_XOR_MULT_DOSStub_d084 {
  strings:
    $key_d084 = { 84 ec [2] f0 f4 [2] b7 f6 [2] f0 e7 [2] be eb [2] b2 e1 [2] a5 ea [2] be a4 [2] 83 }

  condition:
    any of them
}