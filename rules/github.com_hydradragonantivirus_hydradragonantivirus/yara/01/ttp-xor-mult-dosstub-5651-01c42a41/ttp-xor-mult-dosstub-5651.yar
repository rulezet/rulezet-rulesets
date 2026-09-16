rule TTP_XOR_MULT_DOSStub_5651 {
  strings:
    $key_5651 = { 02 39 [2] 76 21 [2] 31 23 [2] 76 32 [2] 38 3e [2] 34 34 [2] 23 3f [2] 38 71 [2] 05 }

  condition:
    any of them
}