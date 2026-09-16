rule TTP_XOR_MULT_DOSStub_50f9 {
  strings:
    $key_50f9 = { 04 91 [2] 70 89 [2] 37 8b [2] 70 9a [2] 3e 96 [2] 32 9c [2] 25 97 [2] 3e d9 [2] 03 }

  condition:
    any of them
}