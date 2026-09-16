rule TTP_XOR_MULT_DOSStub_0045 {
  strings:
    $key_0045 = { 54 2d [2] 20 35 [2] 67 37 [2] 20 26 [2] 6e 2a [2] 62 20 [2] 75 2b [2] 6e 65 [2] 53 }

  condition:
    any of them
}