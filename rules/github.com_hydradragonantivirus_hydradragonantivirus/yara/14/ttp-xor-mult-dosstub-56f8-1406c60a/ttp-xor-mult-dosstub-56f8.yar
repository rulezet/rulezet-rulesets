rule TTP_XOR_MULT_DOSStub_56f8 {
  strings:
    $key_56f8 = { 02 90 [2] 76 88 [2] 31 8a [2] 76 9b [2] 38 97 [2] 34 9d [2] 23 96 [2] 38 d8 [2] 05 }

  condition:
    any of them
}