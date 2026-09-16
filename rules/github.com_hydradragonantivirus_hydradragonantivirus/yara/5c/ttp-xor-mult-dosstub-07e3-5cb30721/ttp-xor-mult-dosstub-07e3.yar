rule TTP_XOR_MULT_DOSStub_07e3 {
  strings:
    $key_07e3 = { 53 8b [2] 27 93 [2] 60 91 [2] 27 80 [2] 69 8c [2] 65 86 [2] 72 8d [2] 69 c3 [2] 54 }

  condition:
    any of them
}