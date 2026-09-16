rule TTP_XOR_MULT_DOSStub_758e {
  strings:
    $key_758e = { 21 e6 [2] 55 fe [2] 12 fc [2] 55 ed [2] 1b e1 [2] 17 eb [2] 00 e0 [2] 1b ae [2] 26 }

  condition:
    any of them
}