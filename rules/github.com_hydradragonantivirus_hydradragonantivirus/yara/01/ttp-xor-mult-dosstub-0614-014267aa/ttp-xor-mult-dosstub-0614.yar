rule TTP_XOR_MULT_DOSStub_0614 {
  strings:
    $key_0614 = { 52 7c [2] 26 64 [2] 61 66 [2] 26 77 [2] 68 7b [2] 64 71 [2] 73 7a [2] 68 34 [2] 55 }

  condition:
    any of them
}