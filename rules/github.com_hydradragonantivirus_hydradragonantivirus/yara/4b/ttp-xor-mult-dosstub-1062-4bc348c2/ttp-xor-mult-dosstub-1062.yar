rule TTP_XOR_MULT_DOSStub_1062 {
  strings:
    $key_1062 = { 44 0a [2] 30 12 [2] 77 10 [2] 30 01 [2] 7e 0d [2] 72 07 [2] 65 0c [2] 7e 42 [2] 43 }

  condition:
    any of them
}