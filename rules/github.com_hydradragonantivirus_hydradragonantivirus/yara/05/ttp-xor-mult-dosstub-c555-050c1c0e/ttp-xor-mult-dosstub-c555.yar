rule TTP_XOR_MULT_DOSStub_c555 {
  strings:
    $key_c555 = { 91 3d [2] e5 25 [2] a2 27 [2] e5 36 [2] ab 3a [2] a7 30 [2] b0 3b [2] ab 75 [2] 96 }

  condition:
    any of them
}