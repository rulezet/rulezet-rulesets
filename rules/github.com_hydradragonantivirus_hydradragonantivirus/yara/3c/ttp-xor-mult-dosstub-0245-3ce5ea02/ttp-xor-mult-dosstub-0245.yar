rule TTP_XOR_MULT_DOSStub_0245 {
  strings:
    $key_0245 = { 56 2d [2] 22 35 [2] 65 37 [2] 22 26 [2] 6c 2a [2] 60 20 [2] 77 2b [2] 6c 65 [2] 51 }

  condition:
    any of them
}