rule TTP_XOR_MULT_DOSStub_7df8 {
  strings:
    $key_7df8 = { 29 90 [2] 5d 88 [2] 1a 8a [2] 5d 9b [2] 13 97 [2] 1f 9d [2] 08 96 [2] 13 d8 [2] 2e }

  condition:
    any of them
}