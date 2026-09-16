rule TTP_XOR_MULT_DOSStub_ae88 {
  strings:
    $key_ae88 = { fa e0 [2] 8e f8 [2] c9 fa [2] 8e eb [2] c0 e7 [2] cc ed [2] db e6 [2] c0 a8 [2] fd }

  condition:
    any of them
}