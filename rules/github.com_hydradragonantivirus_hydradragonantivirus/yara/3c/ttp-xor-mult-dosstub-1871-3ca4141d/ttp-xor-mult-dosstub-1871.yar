rule TTP_XOR_MULT_DOSStub_1871 {
  strings:
    $key_1871 = { 4c 19 [2] 38 01 [2] 7f 03 [2] 38 12 [2] 76 1e [2] 7a 14 [2] 6d 1f [2] 76 51 [2] 4b }

  condition:
    any of them
}