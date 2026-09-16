rule TTP_XOR_MULT_DOSStub_1672 {
  strings:
    $key_1672 = { 42 1a [2] 36 02 [2] 71 00 [2] 36 11 [2] 78 1d [2] 74 17 [2] 63 1c [2] 78 52 [2] 45 }

  condition:
    any of them
}