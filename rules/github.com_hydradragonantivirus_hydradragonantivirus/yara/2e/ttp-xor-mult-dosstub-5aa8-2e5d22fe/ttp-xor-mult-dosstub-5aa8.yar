rule TTP_XOR_MULT_DOSStub_5aa8 {
  strings:
    $key_5aa8 = { 0e c0 [2] 7a d8 [2] 3d da [2] 7a cb [2] 34 c7 [2] 38 cd [2] 2f c6 [2] 34 88 [2] 09 }

  condition:
    any of them
}