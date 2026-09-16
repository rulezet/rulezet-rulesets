rule TTP_XOR_MULT_DOSStub_6be6 {
  strings:
    $key_6be6 = { 3f 8e [2] 4b 96 [2] 0c 94 [2] 4b 85 [2] 05 89 [2] 09 83 [2] 1e 88 [2] 05 c6 [2] 38 }

  condition:
    any of them
}