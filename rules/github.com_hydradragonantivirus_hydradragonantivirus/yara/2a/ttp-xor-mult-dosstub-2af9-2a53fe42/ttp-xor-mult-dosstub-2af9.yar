rule TTP_XOR_MULT_DOSStub_2af9 {
  strings:
    $key_2af9 = { 7e 91 [2] 0a 89 [2] 4d 8b [2] 0a 9a [2] 44 96 [2] 48 9c [2] 5f 97 [2] 44 d9 [2] 79 }

  condition:
    any of them
}