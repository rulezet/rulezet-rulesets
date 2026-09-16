rule TTP_XOR_MULT_DOSStub_3232 {
  strings:
    $key_3232 = { 66 5a [2] 12 42 [2] 55 40 [2] 12 51 [2] 5c 5d [2] 50 57 [2] 47 5c [2] 5c 12 [2] 61 }

  condition:
    any of them
}