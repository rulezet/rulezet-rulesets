rule TTP_XOR_MULT_DOSStub_2742 {
  strings:
    $key_2742 = { 73 2a [2] 07 32 [2] 40 30 [2] 07 21 [2] 49 2d [2] 45 27 [2] 52 2c [2] 49 62 [2] 74 }

  condition:
    any of them
}