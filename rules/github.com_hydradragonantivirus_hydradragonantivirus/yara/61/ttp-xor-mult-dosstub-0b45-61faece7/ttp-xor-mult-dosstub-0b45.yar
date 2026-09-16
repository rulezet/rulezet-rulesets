rule TTP_XOR_MULT_DOSStub_0b45 {
  strings:
    $key_0b45 = { 5f 2d [2] 2b 35 [2] 6c 37 [2] 2b 26 [2] 65 2a [2] 69 20 [2] 7e 2b [2] 65 65 [2] 58 }

  condition:
    any of them
}