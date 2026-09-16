rule TTP_XOR_MULT_DOSStub_6b8e {
  strings:
    $key_6b8e = { 3f e6 [2] 4b fe [2] 0c fc [2] 4b ed [2] 05 e1 [2] 09 eb [2] 1e e0 [2] 05 ae [2] 38 }

  condition:
    any of them
}