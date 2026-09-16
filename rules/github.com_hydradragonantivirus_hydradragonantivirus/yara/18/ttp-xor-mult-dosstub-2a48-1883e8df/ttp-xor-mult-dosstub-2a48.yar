rule TTP_XOR_MULT_DOSStub_2a48 {
  strings:
    $key_2a48 = { 7e 20 [2] 0a 38 [2] 4d 3a [2] 0a 2b [2] 44 27 [2] 48 2d [2] 5f 26 [2] 44 68 [2] 79 }

  condition:
    any of them
}