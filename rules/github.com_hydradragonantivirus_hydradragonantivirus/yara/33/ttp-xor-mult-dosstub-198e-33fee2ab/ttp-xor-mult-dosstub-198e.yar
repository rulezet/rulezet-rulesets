rule TTP_XOR_MULT_DOSStub_198e {
  strings:
    $key_198e = { 4d e6 [2] 39 fe [2] 7e fc [2] 39 ed [2] 77 e1 [2] 7b eb [2] 6c e0 [2] 77 ae [2] 4a }

  condition:
    any of them
}