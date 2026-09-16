rule TTP_XOR_MULT_DOSStub_75e3 {
  strings:
    $key_75e3 = { 21 8b [2] 55 93 [2] 12 91 [2] 55 80 [2] 1b 8c [2] 17 86 [2] 00 8d [2] 1b c3 [2] 26 }

  condition:
    any of them
}