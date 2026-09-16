rule TTP_XOR_MULT_DOSStub_5b63 {
  strings:
    $key_5b63 = { 0f 0b [2] 7b 13 [2] 3c 11 [2] 7b 00 [2] 35 0c [2] 39 06 [2] 2e 0d [2] 35 43 [2] 08 }

  condition:
    any of them
}