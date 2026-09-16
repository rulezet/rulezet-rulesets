rule TTP_XOR_MULT_DOSStub_10e5 {
  strings:
    $key_10e5 = { 44 8d [2] 30 95 [2] 77 97 [2] 30 86 [2] 7e 8a [2] 72 80 [2] 65 8b [2] 7e c5 [2] 43 }

  condition:
    any of them
}