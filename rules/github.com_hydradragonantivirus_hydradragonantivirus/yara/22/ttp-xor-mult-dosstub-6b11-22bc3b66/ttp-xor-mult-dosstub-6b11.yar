rule TTP_XOR_MULT_DOSStub_6b11 {
  strings:
    $key_6b11 = { 3f 79 [2] 4b 61 [2] 0c 63 [2] 4b 72 [2] 05 7e [2] 09 74 [2] 1e 7f [2] 05 31 [2] 38 }

  condition:
    any of them
}