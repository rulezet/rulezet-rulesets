rule TTP_XOR_MULT_DOSStub_fb83 {
  strings:
    $key_fb83 = { af eb [2] db f3 [2] 9c f1 [2] db e0 [2] 95 ec [2] 99 e6 [2] 8e ed [2] 95 a3 [2] a8 }

  condition:
    any of them
}