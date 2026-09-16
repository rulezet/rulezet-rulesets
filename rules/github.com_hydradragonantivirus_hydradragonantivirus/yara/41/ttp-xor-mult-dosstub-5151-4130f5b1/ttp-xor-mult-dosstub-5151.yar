rule TTP_XOR_MULT_DOSStub_5151 {
  strings:
    $key_5151 = { 05 39 [2] 71 21 [2] 36 23 [2] 71 32 [2] 3f 3e [2] 33 34 [2] 24 3f [2] 3f 71 [2] 02 }

  condition:
    any of them
}