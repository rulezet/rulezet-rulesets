rule TTP_XOR_MULT_DOSStub_a48e {
  strings:
    $key_a48e = { f0 e6 [2] 84 fe [2] c3 fc [2] 84 ed [2] ca e1 [2] c6 eb [2] d1 e0 [2] ca ae [2] f7 }

  condition:
    any of them
}