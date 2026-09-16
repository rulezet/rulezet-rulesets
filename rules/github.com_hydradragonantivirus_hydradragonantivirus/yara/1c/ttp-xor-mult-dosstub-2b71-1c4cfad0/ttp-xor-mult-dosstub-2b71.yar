rule TTP_XOR_MULT_DOSStub_2b71 {
  strings:
    $key_2b71 = { 7f 19 [2] 0b 01 [2] 4c 03 [2] 0b 12 [2] 45 1e [2] 49 14 [2] 5e 1f [2] 45 51 [2] 78 }

  condition:
    any of them
}