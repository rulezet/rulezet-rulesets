rule TTP_XOR_MULT_DOSStub_331a {
  strings:
    $key_331a = { 67 72 [2] 13 6a [2] 54 68 [2] 13 79 [2] 5d 75 [2] 51 7f [2] 46 74 [2] 5d 3a [2] 60 }

  condition:
    any of them
}