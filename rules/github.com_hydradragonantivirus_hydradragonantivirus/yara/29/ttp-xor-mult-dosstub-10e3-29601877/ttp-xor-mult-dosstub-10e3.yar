rule TTP_XOR_MULT_DOSStub_10e3 {
  strings:
    $key_10e3 = { 44 8b [2] 30 93 [2] 77 91 [2] 30 80 [2] 7e 8c [2] 72 86 [2] 65 8d [2] 7e c3 [2] 43 }

  condition:
    any of them
}