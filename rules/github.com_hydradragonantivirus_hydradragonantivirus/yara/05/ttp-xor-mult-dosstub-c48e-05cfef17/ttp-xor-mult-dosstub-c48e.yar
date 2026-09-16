rule TTP_XOR_MULT_DOSStub_c48e {
  strings:
    $key_c48e = { 90 e6 [2] e4 fe [2] a3 fc [2] e4 ed [2] aa e1 [2] a6 eb [2] b1 e0 [2] aa ae [2] 97 }

  condition:
    any of them
}