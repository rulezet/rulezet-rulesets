rule TTP_XOR_MULT_DOSStub_d48e {
  strings:
    $key_d48e = { 80 e6 [2] f4 fe [2] b3 fc [2] f4 ed [2] ba e1 [2] b6 eb [2] a1 e0 [2] ba ae [2] 87 }

  condition:
    any of them
}