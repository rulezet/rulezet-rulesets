rule TTP_XOR_MULT_DOSStub_47f4 {
  strings:
    $key_47f4 = { 13 9c [2] 67 84 [2] 20 86 [2] 67 97 [2] 29 9b [2] 25 91 [2] 32 9a [2] 29 d4 [2] 14 }

  condition:
    any of them
}