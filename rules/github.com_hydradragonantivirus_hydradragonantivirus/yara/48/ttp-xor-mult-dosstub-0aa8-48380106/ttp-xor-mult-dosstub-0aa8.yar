rule TTP_XOR_MULT_DOSStub_0aa8 {
  strings:
    $key_0aa8 = { 5e c0 [2] 2a d8 [2] 6d da [2] 2a cb [2] 64 c7 [2] 68 cd [2] 7f c6 [2] 64 88 [2] 59 }

  condition:
    any of them
}