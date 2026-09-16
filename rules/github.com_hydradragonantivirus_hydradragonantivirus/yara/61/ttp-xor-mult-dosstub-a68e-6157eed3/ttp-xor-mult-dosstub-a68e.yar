rule TTP_XOR_MULT_DOSStub_a68e {
  strings:
    $key_a68e = { f2 e6 [2] 86 fe [2] c1 fc [2] 86 ed [2] c8 e1 [2] c4 eb [2] d3 e0 [2] c8 ae [2] f5 }

  condition:
    any of them
}