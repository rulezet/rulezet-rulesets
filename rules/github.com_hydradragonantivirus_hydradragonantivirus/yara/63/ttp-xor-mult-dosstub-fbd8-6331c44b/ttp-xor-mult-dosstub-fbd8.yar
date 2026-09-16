rule TTP_XOR_MULT_DOSStub_fbd8 {
  strings:
    $key_fbd8 = { af b0 [2] db a8 [2] 9c aa [2] db bb [2] 95 b7 [2] 99 bd [2] 8e b6 [2] 95 f8 [2] a8 }

  condition:
    any of them
}