rule TTP_XOR_MULT_DOSStub_67f9 {
  strings:
    $key_67f9 = { 33 91 [2] 47 89 [2] 00 8b [2] 47 9a [2] 09 96 [2] 05 9c [2] 12 97 [2] 09 d9 [2] 34 }

  condition:
    any of them
}