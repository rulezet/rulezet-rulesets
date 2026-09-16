rule TTP_XOR_MULT_DOSStub_468e {
  strings:
    $key_468e = { 12 e6 [2] 66 fe [2] 21 fc [2] 66 ed [2] 28 e1 [2] 24 eb [2] 33 e0 [2] 28 ae [2] 15 }

  condition:
    any of them
}