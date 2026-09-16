rule TTP_XOR_MULT_DOSStub_1025 {
  strings:
    $key_1025 = { 44 4d [2] 30 55 [2] 77 57 [2] 30 46 [2] 7e 4a [2] 72 40 [2] 65 4b [2] 7e 05 [2] 43 }

  condition:
    any of them
}