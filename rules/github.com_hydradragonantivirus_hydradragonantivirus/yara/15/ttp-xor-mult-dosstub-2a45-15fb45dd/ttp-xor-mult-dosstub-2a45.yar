rule TTP_XOR_MULT_DOSStub_2a45 {
  strings:
    $key_2a45 = { 7e 2d [2] 0a 35 [2] 4d 37 [2] 0a 26 [2] 44 2a [2] 48 20 [2] 5f 2b [2] 44 65 [2] 79 }

  condition:
    any of them
}