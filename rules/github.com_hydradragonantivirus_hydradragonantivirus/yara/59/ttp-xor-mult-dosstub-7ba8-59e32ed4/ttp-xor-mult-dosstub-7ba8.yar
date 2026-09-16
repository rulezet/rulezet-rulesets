rule TTP_XOR_MULT_DOSStub_7ba8 {
  strings:
    $key_7ba8 = { 2f c0 [2] 5b d8 [2] 1c da [2] 5b cb [2] 15 c7 [2] 19 cd [2] 0e c6 [2] 15 88 [2] 28 }

  condition:
    any of them
}