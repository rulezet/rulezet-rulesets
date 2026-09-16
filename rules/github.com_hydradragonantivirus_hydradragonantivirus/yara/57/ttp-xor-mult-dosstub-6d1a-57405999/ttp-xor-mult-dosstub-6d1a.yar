rule TTP_XOR_MULT_DOSStub_6d1a {
  strings:
    $key_6d1a = { 39 72 [2] 4d 6a [2] 0a 68 [2] 4d 79 [2] 03 75 [2] 0f 7f [2] 18 74 [2] 03 3a [2] 3e }

  condition:
    any of them
}