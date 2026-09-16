rule TTP_XOR_MULT_DOSStub_3b8e {
  strings:
    $key_3b8e = { 6f e6 [2] 1b fe [2] 5c fc [2] 1b ed [2] 55 e1 [2] 59 eb [2] 4e e0 [2] 55 ae [2] 68 }

  condition:
    any of them
}