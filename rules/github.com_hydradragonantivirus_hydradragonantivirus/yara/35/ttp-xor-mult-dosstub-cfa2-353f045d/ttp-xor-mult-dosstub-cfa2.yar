rule TTP_XOR_MULT_DOSStub_cfa2 {
  strings:
    $key_cfa2 = { 9b ca [2] ef d2 [2] a8 d0 [2] ef c1 [2] a1 cd [2] ad c7 [2] ba cc [2] a1 82 [2] 9c }

  condition:
    any of them
}