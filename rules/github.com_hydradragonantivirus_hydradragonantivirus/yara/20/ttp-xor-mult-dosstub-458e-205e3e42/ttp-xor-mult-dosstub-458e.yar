rule TTP_XOR_MULT_DOSStub_458e {
  strings:
    $key_458e = { 11 e6 [2] 65 fe [2] 22 fc [2] 65 ed [2] 2b e1 [2] 27 eb [2] 30 e0 [2] 2b ae [2] 16 }

  condition:
    any of them
}