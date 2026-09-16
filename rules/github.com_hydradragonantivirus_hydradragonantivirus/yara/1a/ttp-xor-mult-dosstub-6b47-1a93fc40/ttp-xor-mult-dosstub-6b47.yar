rule TTP_XOR_MULT_DOSStub_6b47 {
  strings:
    $key_6b47 = { 3f 2f [2] 4b 37 [2] 0c 35 [2] 4b 24 [2] 05 28 [2] 09 22 [2] 1e 29 [2] 05 67 [2] 38 }

  condition:
    any of them
}