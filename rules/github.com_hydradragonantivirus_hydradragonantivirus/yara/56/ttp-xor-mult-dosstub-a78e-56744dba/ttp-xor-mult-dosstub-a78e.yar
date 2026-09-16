rule TTP_XOR_MULT_DOSStub_a78e {
  strings:
    $key_a78e = { f3 e6 [2] 87 fe [2] c0 fc [2] 87 ed [2] c9 e1 [2] c5 eb [2] d2 e0 [2] c9 ae [2] f4 }

  condition:
    any of them
}