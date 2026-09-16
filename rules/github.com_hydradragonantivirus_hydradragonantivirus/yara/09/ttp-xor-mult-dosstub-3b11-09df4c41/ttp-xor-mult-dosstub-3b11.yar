rule TTP_XOR_MULT_DOSStub_3b11 {
  strings:
    $key_3b11 = { 6f 79 [2] 1b 61 [2] 5c 63 [2] 1b 72 [2] 55 7e [2] 59 74 [2] 4e 7f [2] 55 31 [2] 68 }

  condition:
    any of them
}