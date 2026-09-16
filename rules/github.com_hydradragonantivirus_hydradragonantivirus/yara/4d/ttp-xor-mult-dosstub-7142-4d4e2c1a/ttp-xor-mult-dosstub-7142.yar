rule TTP_XOR_MULT_DOSStub_7142 {
  strings:
    $key_7142 = { 25 2a [2] 51 32 [2] 16 30 [2] 51 21 [2] 1f 2d [2] 13 27 [2] 04 2c [2] 1f 62 [2] 22 }

  condition:
    any of them
}