rule TTP_XOR_MULT_DOSStub_6b63 {
  strings:
    $key_6b63 = { 3f 0b [2] 4b 13 [2] 0c 11 [2] 4b 00 [2] 05 0c [2] 09 06 [2] 1e 0d [2] 05 43 [2] 38 }

  condition:
    any of them
}