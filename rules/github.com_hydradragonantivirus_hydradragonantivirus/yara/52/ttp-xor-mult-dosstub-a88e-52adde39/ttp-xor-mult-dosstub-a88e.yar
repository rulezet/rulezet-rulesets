rule TTP_XOR_MULT_DOSStub_a88e {
  strings:
    $key_a88e = { fc e6 [2] 88 fe [2] cf fc [2] 88 ed [2] c6 e1 [2] ca eb [2] dd e0 [2] c6 ae [2] fb }

  condition:
    any of them
}