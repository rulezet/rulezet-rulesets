rule TTP_XOR_MULT_DOSStub_6b66 {
  strings:
    $key_6b66 = { 3f 0e [2] 4b 16 [2] 0c 14 [2] 4b 05 [2] 05 09 [2] 09 03 [2] 1e 08 [2] 05 46 [2] 38 }

  condition:
    any of them
}