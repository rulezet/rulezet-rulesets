rule TTP_XOR_MULT_DOSStub_51f8 {
  strings:
    $key_51f8 = { 05 90 [2] 71 88 [2] 36 8a [2] 71 9b [2] 3f 97 [2] 33 9d [2] 24 96 [2] 3f d8 [2] 02 }

  condition:
    any of them
}