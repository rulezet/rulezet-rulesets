rule TTP_XOR_MULT_DOSStub_6a56 {
  strings:
    $key_6a56 = { 3e 3e [2] 4a 26 [2] 0d 24 [2] 4a 35 [2] 04 39 [2] 08 33 [2] 1f 38 [2] 04 76 [2] 39 }

  condition:
    any of them
}