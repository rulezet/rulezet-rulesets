rule TTP_XOR_MULT_DOSStub_898e {
  strings:
    $key_898e = { dd e6 [2] a9 fe [2] ee fc [2] a9 ed [2] e7 e1 [2] eb eb [2] fc e0 [2] e7 ae [2] da }

  condition:
    any of them
}