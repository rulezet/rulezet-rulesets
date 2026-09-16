rule TTP_XOR_MULT_DOSStub_478e {
  strings:
    $key_478e = { 13 e6 [2] 67 fe [2] 20 fc [2] 67 ed [2] 29 e1 [2] 25 eb [2] 32 e0 [2] 29 ae [2] 14 }

  condition:
    any of them
}