rule TTP_XOR_MULT_DOSStub_5df4 {
  strings:
    $key_5df4 = { 09 9c [2] 7d 84 [2] 3a 86 [2] 7d 97 [2] 33 9b [2] 3f 91 [2] 28 9a [2] 33 d4 [2] 0e }

  condition:
    any of them
}