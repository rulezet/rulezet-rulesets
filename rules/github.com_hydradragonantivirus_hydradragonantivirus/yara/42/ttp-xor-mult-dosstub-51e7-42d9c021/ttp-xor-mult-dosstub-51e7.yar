rule TTP_XOR_MULT_DOSStub_51e7 {
  strings:
    $key_51e7 = { 05 8f [2] 71 97 [2] 36 95 [2] 71 84 [2] 3f 88 [2] 33 82 [2] 24 89 [2] 3f c7 [2] 02 }

  condition:
    any of them
}