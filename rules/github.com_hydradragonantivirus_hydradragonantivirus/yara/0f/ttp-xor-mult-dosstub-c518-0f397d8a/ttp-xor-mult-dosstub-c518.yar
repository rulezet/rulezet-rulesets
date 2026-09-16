rule TTP_XOR_MULT_DOSStub_c518 {
  strings:
    $key_c518 = { 91 70 [2] e5 68 [2] a2 6a [2] e5 7b [2] ab 77 [2] a7 7d [2] b0 76 [2] ab 38 [2] 96 }

  condition:
    any of them
}