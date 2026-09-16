rule TTP_XOR_MULT_DOSStub_7167 {
  strings:
    $key_7167 = { 25 0f [2] 51 17 [2] 16 15 [2] 51 04 [2] 1f 08 [2] 13 02 [2] 04 09 [2] 1f 47 [2] 22 }

  condition:
    any of them
}