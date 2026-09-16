rule TTP_XOR_MULT_DOSStub_0169 {
  strings:
    $key_0169 = { 55 01 [2] 21 19 [2] 66 1b [2] 21 0a [2] 6f 06 [2] 63 0c [2] 74 07 [2] 6f 49 [2] 52 }

  condition:
    any of them
}