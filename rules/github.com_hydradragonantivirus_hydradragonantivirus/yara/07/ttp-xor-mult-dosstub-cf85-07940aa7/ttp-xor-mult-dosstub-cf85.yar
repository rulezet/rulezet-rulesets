rule TTP_XOR_MULT_DOSStub_cf85 {
  strings:
    $key_cf85 = { 9b ed [2] ef f5 [2] a8 f7 [2] ef e6 [2] a1 ea [2] ad e0 [2] ba eb [2] a1 a5 [2] 9c }

  condition:
    any of them
}