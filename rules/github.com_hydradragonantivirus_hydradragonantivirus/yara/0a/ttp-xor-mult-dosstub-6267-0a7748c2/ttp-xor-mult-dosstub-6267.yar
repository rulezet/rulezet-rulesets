rule TTP_XOR_MULT_DOSStub_6267 {
  strings:
    $key_6267 = { 36 0f [2] 42 17 [2] 05 15 [2] 42 04 [2] 0c 08 [2] 00 02 [2] 17 09 [2] 0c 47 [2] 31 }

  condition:
    any of them
}