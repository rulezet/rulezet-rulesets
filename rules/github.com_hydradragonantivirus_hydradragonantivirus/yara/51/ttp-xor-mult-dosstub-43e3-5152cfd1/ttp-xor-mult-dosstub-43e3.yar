rule TTP_XOR_MULT_DOSStub_43e3 {
  strings:
    $key_43e3 = { 17 8b [2] 63 93 [2] 24 91 [2] 63 80 [2] 2d 8c [2] 21 86 [2] 36 8d [2] 2d c3 [2] 10 }

  condition:
    any of them
}