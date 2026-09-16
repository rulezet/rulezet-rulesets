rule TTP_XOR_MULT_DOSStub_67f4 {
  strings:
    $key_67f4 = { 33 9c [2] 47 84 [2] 00 86 [2] 47 97 [2] 09 9b [2] 05 91 [2] 12 9a [2] 09 d4 [2] 34 }

  condition:
    any of them
}