rule TTP_XOR_MULT_DOSStub_0114 {
  strings:
    $key_0114 = { 55 7c [2] 21 64 [2] 66 66 [2] 21 77 [2] 6f 7b [2] 63 71 [2] 74 7a [2] 6f 34 [2] 52 }

  condition:
    any of them
}