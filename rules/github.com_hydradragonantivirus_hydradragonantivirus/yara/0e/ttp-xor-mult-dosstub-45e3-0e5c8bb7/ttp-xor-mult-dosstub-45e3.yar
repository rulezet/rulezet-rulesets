rule TTP_XOR_MULT_DOSStub_45e3 {
  strings:
    $key_45e3 = { 11 8b [2] 65 93 [2] 22 91 [2] 65 80 [2] 2b 8c [2] 27 86 [2] 30 8d [2] 2b c3 [2] 16 }

  condition:
    any of them
}