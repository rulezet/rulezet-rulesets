rule TTP_XOR_MULT_DOSStub_60e3 {
  strings:
    $key_60e3 = { 34 8b [2] 40 93 [2] 07 91 [2] 40 80 [2] 0e 8c [2] 02 86 [2] 15 8d [2] 0e c3 [2] 33 }

  condition:
    any of them
}