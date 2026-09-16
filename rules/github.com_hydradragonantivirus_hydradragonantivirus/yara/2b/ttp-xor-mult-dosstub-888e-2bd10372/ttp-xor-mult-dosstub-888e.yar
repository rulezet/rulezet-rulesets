rule TTP_XOR_MULT_DOSStub_888e {
  strings:
    $key_888e = { dc e6 [2] a8 fe [2] ef fc [2] a8 ed [2] e6 e1 [2] ea eb [2] fd e0 [2] e6 ae [2] db }

  condition:
    any of them
}