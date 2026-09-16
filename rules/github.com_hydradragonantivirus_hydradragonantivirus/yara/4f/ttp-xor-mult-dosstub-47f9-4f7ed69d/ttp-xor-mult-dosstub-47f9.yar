rule TTP_XOR_MULT_DOSStub_47f9 {
  strings:
    $key_47f9 = { 13 91 [2] 67 89 [2] 20 8b [2] 67 9a [2] 29 96 [2] 25 9c [2] 32 97 [2] 29 d9 [2] 14 }

  condition:
    any of them
}