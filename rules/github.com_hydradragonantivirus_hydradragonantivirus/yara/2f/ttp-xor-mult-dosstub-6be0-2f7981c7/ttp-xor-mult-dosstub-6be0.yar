rule TTP_XOR_MULT_DOSStub_6be0 {
  strings:
    $key_6be0 = { 3f 88 [2] 4b 90 [2] 0c 92 [2] 4b 83 [2] 05 8f [2] 09 85 [2] 1e 8e [2] 05 c0 [2] 38 }

  condition:
    any of them
}