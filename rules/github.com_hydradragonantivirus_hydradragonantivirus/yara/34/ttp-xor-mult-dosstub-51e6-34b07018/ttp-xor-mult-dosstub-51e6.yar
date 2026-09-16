rule TTP_XOR_MULT_DOSStub_51e6 {
  strings:
    $key_51e6 = { 05 8e [2] 71 96 [2] 36 94 [2] 71 85 [2] 3f 89 [2] 33 83 [2] 24 88 [2] 3f c6 [2] 02 }

  condition:
    any of them
}