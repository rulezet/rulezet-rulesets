rule TTP_XOR_MULT_DOSStub_268e {
  strings:
    $key_268e = { 72 e6 [2] 06 fe [2] 41 fc [2] 06 ed [2] 48 e1 [2] 44 eb [2] 53 e0 [2] 48 ae [2] 75 }

  condition:
    any of them
}