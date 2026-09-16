rule TTP_XOR_MULT_DOSStub_7b01 {
  strings:
    $key_7b01 = { 2f 69 [2] 5b 71 [2] 1c 73 [2] 5b 62 [2] 15 6e [2] 19 64 [2] 0e 6f [2] 15 21 [2] 28 }

  condition:
    any of them
}