rule TTP_XOR_MULT_DOSStub_51f9 {
  strings:
    $key_51f9 = { 05 91 [2] 71 89 [2] 36 8b [2] 71 9a [2] 3f 96 [2] 33 9c [2] 24 97 [2] 3f d9 [2] 02 }

  condition:
    any of them
}