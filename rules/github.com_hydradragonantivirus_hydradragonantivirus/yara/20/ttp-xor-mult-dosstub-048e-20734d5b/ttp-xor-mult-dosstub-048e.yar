rule TTP_XOR_MULT_DOSStub_048e {
  strings:
    $key_048e = { 50 e6 [2] 24 fe [2] 63 fc [2] 24 ed [2] 6a e1 [2] 66 eb [2] 71 e0 [2] 6a ae [2] 57 }

  condition:
    any of them
}