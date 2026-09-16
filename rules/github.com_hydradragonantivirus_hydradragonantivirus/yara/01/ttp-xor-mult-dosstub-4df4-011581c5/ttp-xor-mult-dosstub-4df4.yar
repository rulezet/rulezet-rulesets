rule TTP_XOR_MULT_DOSStub_4df4 {
  strings:
    $key_4df4 = { 19 9c [2] 6d 84 [2] 2a 86 [2] 6d 97 [2] 23 9b [2] 2f 91 [2] 38 9a [2] 23 d4 [2] 1e }

  condition:
    any of them
}