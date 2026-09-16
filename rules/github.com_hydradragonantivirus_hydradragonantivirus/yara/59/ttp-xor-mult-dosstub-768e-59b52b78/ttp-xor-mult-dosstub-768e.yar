rule TTP_XOR_MULT_DOSStub_768e {
  strings:
    $key_768e = { 22 e6 [2] 56 fe [2] 11 fc [2] 56 ed [2] 18 e1 [2] 14 eb [2] 03 e0 [2] 18 ae [2] 25 }

  condition:
    any of them
}