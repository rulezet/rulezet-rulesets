rule TTP_XOR_MULT_DOSStub_64f9 {
  strings:
    $key_64f9 = { 30 91 [2] 44 89 [2] 03 8b [2] 44 9a [2] 0a 96 [2] 06 9c [2] 11 97 [2] 0a d9 [2] 37 }

  condition:
    any of them
}