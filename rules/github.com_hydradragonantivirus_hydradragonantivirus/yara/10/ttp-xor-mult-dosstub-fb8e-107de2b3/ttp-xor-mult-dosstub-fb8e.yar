rule TTP_XOR_MULT_DOSStub_fb8e {
  strings:
    $key_fb8e = { af e6 [2] db fe [2] 9c fc [2] db ed [2] 95 e1 [2] 99 eb [2] 8e e0 [2] 95 ae [2] a8 }

  condition:
    any of them
}