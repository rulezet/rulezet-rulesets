rule TTP_XOR_MULT_DOSStub_0173 {
  strings:
    $key_0173 = { 55 1b [2] 21 03 [2] 66 01 [2] 21 10 [2] 6f 1c [2] 63 16 [2] 74 1d [2] 6f 53 [2] 52 }

  condition:
    any of them
}