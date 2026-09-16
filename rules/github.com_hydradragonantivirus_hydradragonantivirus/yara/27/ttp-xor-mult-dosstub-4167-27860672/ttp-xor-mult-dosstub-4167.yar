rule TTP_XOR_MULT_DOSStub_4167 {
  strings:
    $key_4167 = { 15 0f [2] 61 17 [2] 26 15 [2] 61 04 [2] 2f 08 [2] 23 02 [2] 34 09 [2] 2f 47 [2] 12 }

  condition:
    any of them
}