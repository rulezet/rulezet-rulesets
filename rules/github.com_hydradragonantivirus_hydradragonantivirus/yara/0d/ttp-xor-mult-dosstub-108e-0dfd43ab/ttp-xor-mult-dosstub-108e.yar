rule TTP_XOR_MULT_DOSStub_108e {
  strings:
    $key_108e = { 44 e6 [2] 30 fe [2] 77 fc [2] 30 ed [2] 7e e1 [2] 72 eb [2] 65 e0 [2] 7e ae [2] 43 }

  condition:
    any of them
}