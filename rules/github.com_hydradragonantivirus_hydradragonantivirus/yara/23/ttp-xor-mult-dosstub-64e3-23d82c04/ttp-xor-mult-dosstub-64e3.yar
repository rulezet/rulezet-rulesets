rule TTP_XOR_MULT_DOSStub_64e3 {
  strings:
    $key_64e3 = { 30 8b [2] 44 93 [2] 03 91 [2] 44 80 [2] 0a 8c [2] 06 86 [2] 11 8d [2] 0a c3 [2] 37 }

  condition:
    any of them
}