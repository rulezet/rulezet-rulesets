rule TTP_XOR_MULT_DOSStub_09f8 {
  strings:
    $key_09f8 = { 5d 90 [2] 29 88 [2] 6e 8a [2] 29 9b [2] 67 97 [2] 6b 9d [2] 7c 96 [2] 67 d8 [2] 5a }

  condition:
    any of them
}