rule TTP_XOR_MULT_DOSStub_cf8c {
  strings:
    $key_cf8c = { 9b e4 [2] ef fc [2] a8 fe [2] ef ef [2] a1 e3 [2] ad e9 [2] ba e2 [2] a1 ac [2] 9c }

  condition:
    any of them
}