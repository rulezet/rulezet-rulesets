rule TTP_XOR_MULT_DOSStub_6a70 {
  strings:
    $key_6a70 = { 3e 18 [2] 4a 00 [2] 0d 02 [2] 4a 13 [2] 04 1f [2] 08 15 [2] 1f 1e [2] 04 50 [2] 39 }

  condition:
    any of them
}