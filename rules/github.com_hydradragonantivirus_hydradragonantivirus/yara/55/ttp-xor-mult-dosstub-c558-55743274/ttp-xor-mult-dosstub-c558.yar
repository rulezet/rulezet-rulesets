rule TTP_XOR_MULT_DOSStub_c558 {
  strings:
    $key_c558 = { 91 30 [2] e5 28 [2] a2 2a [2] e5 3b [2] ab 37 [2] a7 3d [2] b0 36 [2] ab 78 [2] 96 }

  condition:
    any of them
}