rule TTP_XOR_MULT_DOSStub_6b01 {
  strings:
    $key_6b01 = { 3f 69 [2] 4b 71 [2] 0c 73 [2] 4b 62 [2] 05 6e [2] 09 64 [2] 1e 6f [2] 05 21 [2] 38 }

  condition:
    any of them
}