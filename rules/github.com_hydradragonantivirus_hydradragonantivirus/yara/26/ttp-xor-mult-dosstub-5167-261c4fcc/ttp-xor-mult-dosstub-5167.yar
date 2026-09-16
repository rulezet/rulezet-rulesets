rule TTP_XOR_MULT_DOSStub_5167 {
  strings:
    $key_5167 = { 05 0f [2] 71 17 [2] 36 15 [2] 71 04 [2] 3f 08 [2] 33 02 [2] 24 09 [2] 3f 47 [2] 02 }

  condition:
    any of them
}