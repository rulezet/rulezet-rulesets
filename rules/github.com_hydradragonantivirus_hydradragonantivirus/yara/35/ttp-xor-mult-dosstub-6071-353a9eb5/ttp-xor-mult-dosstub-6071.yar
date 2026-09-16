rule TTP_XOR_MULT_DOSStub_6071 {
  strings:
    $key_6071 = { 34 19 [2] 40 01 [2] 07 03 [2] 40 12 [2] 0e 1e [2] 02 14 [2] 15 1f [2] 0e 51 [2] 33 }

  condition:
    any of them
}