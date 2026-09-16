rule TTP_XOR_MULT_DOSStub_5120 {
  strings:
    $key_5120 = { 05 48 [2] 71 50 [2] 36 52 [2] 71 43 [2] 3f 4f [2] 33 45 [2] 24 4e [2] 3f 00 [2] 02 }

  condition:
    any of them
}