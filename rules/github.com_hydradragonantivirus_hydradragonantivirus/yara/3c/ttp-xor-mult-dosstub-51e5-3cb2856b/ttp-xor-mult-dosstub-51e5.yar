rule TTP_XOR_MULT_DOSStub_51e5 {
  strings:
    $key_51e5 = { 05 8d [2] 71 95 [2] 36 97 [2] 71 86 [2] 3f 8a [2] 33 80 [2] 24 8b [2] 3f c5 [2] 02 }

  condition:
    any of them
}