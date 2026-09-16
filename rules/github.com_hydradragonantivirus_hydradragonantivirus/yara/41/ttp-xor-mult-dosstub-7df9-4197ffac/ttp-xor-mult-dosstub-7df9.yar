rule TTP_XOR_MULT_DOSStub_7df9 {
  strings:
    $key_7df9 = { 29 91 [2] 5d 89 [2] 1a 8b [2] 5d 9a [2] 13 96 [2] 1f 9c [2] 08 97 [2] 13 d9 [2] 2e }

  condition:
    any of them
}