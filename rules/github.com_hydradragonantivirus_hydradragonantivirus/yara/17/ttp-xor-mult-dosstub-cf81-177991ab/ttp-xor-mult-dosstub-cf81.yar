rule TTP_XOR_MULT_DOSStub_cf81 {
  strings:
    $key_cf81 = { 9b e9 [2] ef f1 [2] a8 f3 [2] ef e2 [2] a1 ee [2] ad e4 [2] ba ef [2] a1 a1 [2] 9c }

  condition:
    any of them
}