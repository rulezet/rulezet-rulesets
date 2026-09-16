rule TTP_XOR_MULT_DOSStub_78f9 {
  strings:
    $key_78f9 = { 2c 91 [2] 58 89 [2] 1f 8b [2] 58 9a [2] 16 96 [2] 1a 9c [2] 0d 97 [2] 16 d9 [2] 2b }

  condition:
    any of them
}