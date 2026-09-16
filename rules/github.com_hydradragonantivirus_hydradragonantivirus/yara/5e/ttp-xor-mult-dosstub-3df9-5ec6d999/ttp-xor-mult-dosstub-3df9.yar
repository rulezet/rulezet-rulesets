rule TTP_XOR_MULT_DOSStub_3df9 {
  strings:
    $key_3df9 = { 69 91 [2] 1d 89 [2] 5a 8b [2] 1d 9a [2] 53 96 [2] 5f 9c [2] 48 97 [2] 53 d9 [2] 6e }

  condition:
    any of them
}