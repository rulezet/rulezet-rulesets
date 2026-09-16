rule TTP_XOR_MULT_DOSStub_231a {
  strings:
    $key_231a = { 77 72 [2] 03 6a [2] 44 68 [2] 03 79 [2] 4d 75 [2] 41 7f [2] 56 74 [2] 4d 3a [2] 70 }

  condition:
    any of them
}