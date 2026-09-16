rule TTP_XOR_MULT_DOSStub_4aa8 {
  strings:
    $key_4aa8 = { 1e c0 [2] 6a d8 [2] 2d da [2] 6a cb [2] 24 c7 [2] 28 cd [2] 3f c6 [2] 24 88 [2] 19 }

  condition:
    any of them
}