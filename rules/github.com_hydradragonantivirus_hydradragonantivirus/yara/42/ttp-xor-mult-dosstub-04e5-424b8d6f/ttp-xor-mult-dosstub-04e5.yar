rule TTP_XOR_MULT_DOSStub_04e5 {
  strings:
    $key_04e5 = { 50 8d [2] 24 95 [2] 63 97 [2] 24 86 [2] 6a 8a [2] 66 80 [2] 71 8b [2] 6a c5 [2] 57 }

  condition:
    any of them
}