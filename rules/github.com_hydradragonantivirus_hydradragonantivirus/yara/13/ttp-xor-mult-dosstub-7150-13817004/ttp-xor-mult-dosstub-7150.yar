rule TTP_XOR_MULT_DOSStub_7150 {
  strings:
    $key_7150 = { 25 38 [2] 51 20 [2] 16 22 [2] 51 33 [2] 1f 3f [2] 13 35 [2] 04 3e [2] 1f 70 [2] 22 }

  condition:
    any of them
}