rule TTP_XOR_MULT_DOSStub_32e3 {
  strings:
    $key_32e3 = { 66 8b [2] 12 93 [2] 55 91 [2] 12 80 [2] 5c 8c [2] 50 86 [2] 47 8d [2] 5c c3 [2] 61 }

  condition:
    any of them
}