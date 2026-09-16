rule TTP_XOR_MULT_DOSStub_4b44 {
  strings:
    $key_4b44 = { 1f 2c [2] 6b 34 [2] 2c 36 [2] 6b 27 [2] 25 2b [2] 29 21 [2] 3e 2a [2] 25 64 [2] 18 }

  condition:
    any of them
}