rule TTP_XOR_MULT_DOSStub_50f2 {
  strings:
    $key_50f2 = { 04 9a [2] 70 82 [2] 37 80 [2] 70 91 [2] 3e 9d [2] 32 97 [2] 25 9c [2] 3e d2 [2] 03 }

  condition:
    any of them
}