rule TTP_XOR_MULT_DOSStub_1a11 {
  strings:
    $key_1a11 = { 4e 79 [2] 3a 61 [2] 7d 63 [2] 3a 72 [2] 74 7e [2] 78 74 [2] 6f 7f [2] 74 31 [2] 49 }

  condition:
    any of them
}