rule TTP_XOR_MULT_DOSStub_47e3 {
  strings:
    $key_47e3 = { 13 8b [2] 67 93 [2] 20 91 [2] 67 80 [2] 29 8c [2] 25 86 [2] 32 8d [2] 29 c3 [2] 14 }

  condition:
    any of them
}