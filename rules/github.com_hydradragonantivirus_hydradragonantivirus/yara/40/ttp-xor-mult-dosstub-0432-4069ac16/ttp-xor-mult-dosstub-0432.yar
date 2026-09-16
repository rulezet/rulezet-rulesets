rule TTP_XOR_MULT_DOSStub_0432 {
  strings:
    $key_0432 = { 50 5a [2] 24 42 [2] 63 40 [2] 24 51 [2] 6a 5d [2] 66 57 [2] 71 5c [2] 6a 12 [2] 57 }

  condition:
    any of them
}