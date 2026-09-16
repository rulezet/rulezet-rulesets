rule TTP_XOR_MULT_DOSStub_388e {
  strings:
    $key_388e = { 6c e6 [2] 18 fe [2] 5f fc [2] 18 ed [2] 56 e1 [2] 5a eb [2] 4d e0 [2] 56 ae [2] 6b }

  condition:
    any of them
}