rule TTP_XOR_MULT_DOSStub_2749 {
  strings:
    $key_2749 = { 73 21 [2] 07 39 [2] 40 3b [2] 07 2a [2] 49 26 [2] 45 2c [2] 52 27 [2] 49 69 [2] 74 }

  condition:
    any of them
}