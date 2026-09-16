rule TTP_XOR_MULT_DOSStub_3732 {
  strings:
    $key_3732 = { 63 5a [2] 17 42 [2] 50 40 [2] 17 51 [2] 59 5d [2] 55 57 [2] 42 5c [2] 59 12 [2] 64 }

  condition:
    any of them
}