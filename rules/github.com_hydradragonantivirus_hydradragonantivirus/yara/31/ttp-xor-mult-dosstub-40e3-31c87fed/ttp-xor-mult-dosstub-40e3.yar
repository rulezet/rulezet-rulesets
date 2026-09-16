rule TTP_XOR_MULT_DOSStub_40e3 {
  strings:
    $key_40e3 = { 14 8b [2] 60 93 [2] 27 91 [2] 60 80 [2] 2e 8c [2] 22 86 [2] 35 8d [2] 2e c3 [2] 13 }

  condition:
    any of them
}