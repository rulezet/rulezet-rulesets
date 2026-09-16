rule TTP_XOR_MULT_DOSStub_6c25 {
  strings:
    $key_6c25 = { 38 4d [2] 4c 55 [2] 0b 57 [2] 4c 46 [2] 02 4a [2] 0e 40 [2] 19 4b [2] 02 05 [2] 3f }

  condition:
    any of them
}