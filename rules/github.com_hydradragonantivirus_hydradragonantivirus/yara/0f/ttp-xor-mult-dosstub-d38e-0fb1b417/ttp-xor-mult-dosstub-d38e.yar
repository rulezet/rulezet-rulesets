rule TTP_XOR_MULT_DOSStub_d38e {
  strings:
    $key_d38e = { 87 e6 [2] f3 fe [2] b4 fc [2] f3 ed [2] bd e1 [2] b1 eb [2] a6 e0 [2] bd ae [2] 80 }

  condition:
    any of them
}