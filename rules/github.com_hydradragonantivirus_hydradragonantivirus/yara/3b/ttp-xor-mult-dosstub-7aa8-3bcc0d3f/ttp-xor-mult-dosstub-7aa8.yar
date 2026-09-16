rule TTP_XOR_MULT_DOSStub_7aa8 {
  strings:
    $key_7aa8 = { 2e c0 [2] 5a d8 [2] 1d da [2] 5a cb [2] 14 c7 [2] 18 cd [2] 0f c6 [2] 14 88 [2] 29 }

  condition:
    any of them
}