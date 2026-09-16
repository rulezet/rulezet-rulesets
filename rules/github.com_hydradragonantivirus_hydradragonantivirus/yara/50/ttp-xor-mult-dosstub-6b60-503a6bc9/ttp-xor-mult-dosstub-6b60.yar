rule TTP_XOR_MULT_DOSStub_6b60 {
  strings:
    $key_6b60 = { 3f 08 [2] 4b 10 [2] 0c 12 [2] 4b 03 [2] 05 0f [2] 09 05 [2] 1e 0e [2] 05 40 [2] 38 }

  condition:
    any of them
}