rule TTP_XOR_MULT_DOSStub_43ce {
  strings:
    $key_43ce = { 17 a6 [2] 63 be [2] 24 bc [2] 63 ad [2] 2d a1 [2] 21 ab [2] 36 a0 [2] 2d ee [2] 10 }

  condition:
    any of them
}