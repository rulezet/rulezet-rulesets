rule TTP_XOR_MULT_DOSStub_6c28 {
  strings:
    $key_6c28 = { 38 40 [2] 4c 58 [2] 0b 5a [2] 4c 4b [2] 02 47 [2] 0e 4d [2] 19 46 [2] 02 08 [2] 3f }

  condition:
    any of them
}