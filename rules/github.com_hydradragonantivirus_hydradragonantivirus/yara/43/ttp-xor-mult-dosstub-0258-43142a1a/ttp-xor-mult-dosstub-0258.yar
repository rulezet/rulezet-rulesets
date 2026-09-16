rule TTP_XOR_MULT_DOSStub_0258 {
  strings:
    $key_0258 = { 56 30 [2] 22 28 [2] 65 2a [2] 22 3b [2] 6c 37 [2] 60 3d [2] 77 36 [2] 6c 78 [2] 51 }

  condition:
    any of them
}