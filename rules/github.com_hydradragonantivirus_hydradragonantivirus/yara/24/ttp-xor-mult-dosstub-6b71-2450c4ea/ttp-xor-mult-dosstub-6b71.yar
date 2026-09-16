rule TTP_XOR_MULT_DOSStub_6b71 {
  strings:
    $key_6b71 = { 3f 19 [2] 4b 01 [2] 0c 03 [2] 4b 12 [2] 05 1e [2] 09 14 [2] 1e 1f [2] 05 51 [2] 38 }

  condition:
    any of them
}