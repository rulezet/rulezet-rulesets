rule TTP_XOR_MULT_DOSStub_c78e {
  strings:
    $key_c78e = { 93 e6 [2] e7 fe [2] a0 fc [2] e7 ed [2] a9 e1 [2] a5 eb [2] b2 e0 [2] a9 ae [2] 94 }

  condition:
    any of them
}