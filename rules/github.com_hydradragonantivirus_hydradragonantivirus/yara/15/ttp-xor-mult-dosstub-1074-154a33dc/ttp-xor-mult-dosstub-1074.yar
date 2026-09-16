rule TTP_XOR_MULT_DOSStub_1074 {
  strings:
    $key_1074 = { 44 1c [2] 30 04 [2] 77 06 [2] 30 17 [2] 7e 1b [2] 72 11 [2] 65 1a [2] 7e 54 [2] 43 }

  condition:
    any of them
}