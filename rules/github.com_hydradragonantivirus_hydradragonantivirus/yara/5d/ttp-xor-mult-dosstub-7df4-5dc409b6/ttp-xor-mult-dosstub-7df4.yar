rule TTP_XOR_MULT_DOSStub_7df4 {
  strings:
    $key_7df4 = { 29 9c [2] 5d 84 [2] 1a 86 [2] 5d 97 [2] 13 9b [2] 1f 91 [2] 08 9a [2] 13 d4 [2] 2e }

  condition:
    any of them
}