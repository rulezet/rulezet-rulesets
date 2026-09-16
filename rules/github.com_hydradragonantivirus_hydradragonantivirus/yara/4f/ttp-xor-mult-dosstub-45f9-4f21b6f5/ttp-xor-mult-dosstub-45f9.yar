rule TTP_XOR_MULT_DOSStub_45f9 {
  strings:
    $key_45f9 = { 11 91 [2] 65 89 [2] 22 8b [2] 65 9a [2] 2b 96 [2] 27 9c [2] 30 97 [2] 2b d9 [2] 16 }

  condition:
    any of them
}