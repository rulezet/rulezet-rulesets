rule TTP_XOR_MULT_DOSStub_32f4 {
  strings:
    $key_32f4 = { 66 9c [2] 12 84 [2] 55 86 [2] 12 97 [2] 5c 9b [2] 50 91 [2] 47 9a [2] 5c d4 [2] 61 }

  condition:
    any of them
}