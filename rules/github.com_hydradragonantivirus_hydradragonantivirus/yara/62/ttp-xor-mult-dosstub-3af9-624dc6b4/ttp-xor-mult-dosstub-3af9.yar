rule TTP_XOR_MULT_DOSStub_3af9 {
  strings:
    $key_3af9 = { 6e 91 [2] 1a 89 [2] 5d 8b [2] 1a 9a [2] 54 96 [2] 58 9c [2] 4f 97 [2] 54 d9 [2] 69 }

  condition:
    any of them
}