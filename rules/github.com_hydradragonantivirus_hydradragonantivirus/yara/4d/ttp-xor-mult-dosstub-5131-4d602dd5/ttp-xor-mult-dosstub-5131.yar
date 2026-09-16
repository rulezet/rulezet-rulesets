rule TTP_XOR_MULT_DOSStub_5131 {
  strings:
    $key_5131 = { 05 59 [2] 71 41 [2] 36 43 [2] 71 52 [2] 3f 5e [2] 33 54 [2] 24 5f [2] 3f 11 [2] 02 }

  condition:
    any of them
}