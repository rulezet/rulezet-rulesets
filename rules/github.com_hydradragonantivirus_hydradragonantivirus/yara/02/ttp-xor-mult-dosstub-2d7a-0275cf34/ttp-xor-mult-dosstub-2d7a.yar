rule TTP_XOR_MULT_DOSStub_2d7a {
  strings:
    $key_2d7a = { 79 12 [2] 0d 0a [2] 4a 08 [2] 0d 19 [2] 43 15 [2] 4f 1f [2] 58 14 [2] 43 5a [2] 7e }

  condition:
    any of them
}