rule TTP_XOR_MULT_DOSStub_3032 {
  strings:
    $key_3032 = { 64 5a [2] 10 42 [2] 57 40 [2] 10 51 [2] 5e 5d [2] 52 57 [2] 45 5c [2] 5e 12 [2] 63 }

  condition:
    any of them
}