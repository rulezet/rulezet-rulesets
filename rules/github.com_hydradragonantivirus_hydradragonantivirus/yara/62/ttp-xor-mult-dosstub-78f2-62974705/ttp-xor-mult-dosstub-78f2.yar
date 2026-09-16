rule TTP_XOR_MULT_DOSStub_78f2 {
  strings:
    $key_78f2 = { 2c 9a [2] 58 82 [2] 1f 80 [2] 58 91 [2] 16 9d [2] 1a 97 [2] 0d 9c [2] 16 d2 [2] 2b }

  condition:
    any of them
}