rule TTP_XOR_MULT_DOSStub_63e1 {
  strings:
    $key_63e1 = { 37 89 [2] 43 91 [2] 04 93 [2] 43 82 [2] 0d 8e [2] 01 84 [2] 16 8f [2] 0d c1 [2] 30 }

  condition:
    any of them
}