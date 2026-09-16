rule TTP_XOR_MULT_DOSStub_2b01 {
  strings:
    $key_2b01 = { 7f 69 [2] 0b 71 [2] 4c 73 [2] 0b 62 [2] 45 6e [2] 49 64 [2] 5e 6f [2] 45 21 [2] 78 }

  condition:
    any of them
}