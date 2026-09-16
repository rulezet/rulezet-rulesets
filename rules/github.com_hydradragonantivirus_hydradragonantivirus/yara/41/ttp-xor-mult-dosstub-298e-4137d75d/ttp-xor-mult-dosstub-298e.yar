rule TTP_XOR_MULT_DOSStub_298e {
  strings:
    $key_298e = { 7d e6 [2] 09 fe [2] 4e fc [2] 09 ed [2] 47 e1 [2] 4b eb [2] 5c e0 [2] 47 ae [2] 7a }

  condition:
    any of them
}