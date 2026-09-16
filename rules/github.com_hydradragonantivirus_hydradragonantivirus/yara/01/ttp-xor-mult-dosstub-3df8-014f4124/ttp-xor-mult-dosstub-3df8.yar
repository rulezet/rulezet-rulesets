rule TTP_XOR_MULT_DOSStub_3df8 {
  strings:
    $key_3df8 = { 69 90 [2] 1d 88 [2] 5a 8a [2] 1d 9b [2] 53 97 [2] 5f 9d [2] 48 96 [2] 53 d8 [2] 6e }

  condition:
    any of them
}