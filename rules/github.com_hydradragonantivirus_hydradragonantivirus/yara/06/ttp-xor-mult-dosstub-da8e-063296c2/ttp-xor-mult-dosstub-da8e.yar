rule TTP_XOR_MULT_DOSStub_da8e {
  strings:
    $key_da8e = { 8e e6 [2] fa fe [2] bd fc [2] fa ed [2] b4 e1 [2] b8 eb [2] af e0 [2] b4 ae [2] 89 }

  condition:
    any of them
}