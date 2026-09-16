rule TTP_XOR_MULT_DOSStub_6d4a {
  strings:
    $key_6d4a = { 39 22 [2] 4d 3a [2] 0a 38 [2] 4d 29 [2] 03 25 [2] 0f 2f [2] 18 24 [2] 03 6a [2] 3e }

  condition:
    any of them
}