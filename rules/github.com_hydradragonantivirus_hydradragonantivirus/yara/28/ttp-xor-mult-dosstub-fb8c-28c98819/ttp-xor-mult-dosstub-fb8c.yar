rule TTP_XOR_MULT_DOSStub_fb8c {
  strings:
    $key_fb8c = { af e4 [2] db fc [2] 9c fe [2] db ef [2] 95 e3 [2] 99 e9 [2] 8e e2 [2] 95 ac [2] a8 }

  condition:
    any of them
}