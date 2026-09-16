rule TTP_XOR_MULT_DOSStub_258e {
  strings:
    $key_258e = { 71 e6 [2] 05 fe [2] 42 fc [2] 05 ed [2] 4b e1 [2] 47 eb [2] 50 e0 [2] 4b ae [2] 76 }

  condition:
    any of them
}