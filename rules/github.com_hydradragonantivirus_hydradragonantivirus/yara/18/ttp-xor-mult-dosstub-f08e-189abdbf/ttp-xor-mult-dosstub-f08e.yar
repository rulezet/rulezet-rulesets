rule TTP_XOR_MULT_DOSStub_f08e {
  strings:
    $key_f08e = { a4 e6 [2] d0 fe [2] 97 fc [2] d0 ed [2] 9e e1 [2] 92 eb [2] 85 e0 [2] 9e ae [2] a3 }

  condition:
    any of them
}