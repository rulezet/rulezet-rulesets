rule TTP_XOR_MULT_DOSStub_0745 {
  strings:
    $key_0745 = { 53 2d [2] 27 35 [2] 60 37 [2] 27 26 [2] 69 2a [2] 65 20 [2] 72 2b [2] 69 65 [2] 54 }

  condition:
    any of them
}