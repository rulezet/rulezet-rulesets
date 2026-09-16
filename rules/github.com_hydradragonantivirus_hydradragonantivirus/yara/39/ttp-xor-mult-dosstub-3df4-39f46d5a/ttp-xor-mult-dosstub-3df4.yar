rule TTP_XOR_MULT_DOSStub_3df4 {
  strings:
    $key_3df4 = { 69 9c [2] 1d 84 [2] 5a 86 [2] 1d 97 [2] 53 9b [2] 5f 91 [2] 48 9a [2] 53 d4 [2] 6e }

  condition:
    any of them
}