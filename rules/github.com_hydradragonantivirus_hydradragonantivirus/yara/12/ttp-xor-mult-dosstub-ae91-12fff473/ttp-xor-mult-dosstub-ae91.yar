rule TTP_XOR_MULT_DOSStub_ae91 {
  strings:
    $key_ae91 = { fa f9 [2] 8e e1 [2] c9 e3 [2] 8e f2 [2] c0 fe [2] cc f4 [2] db ff [2] c0 b1 [2] fd }

  condition:
    any of them
}