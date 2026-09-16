rule TTP_XOR_MULT_DOSStub_5157 {
  strings:
    $key_5157 = { 05 3f [2] 71 27 [2] 36 25 [2] 71 34 [2] 3f 38 [2] 33 32 [2] 24 39 [2] 3f 77 [2] 02 }

  condition:
    any of them
}