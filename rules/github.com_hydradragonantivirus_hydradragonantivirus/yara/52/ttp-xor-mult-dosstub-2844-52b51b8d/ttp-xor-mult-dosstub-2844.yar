rule TTP_XOR_MULT_DOSStub_2844 {
  strings:
    $key_2844 = { 7c 2c [2] 08 34 [2] 4f 36 [2] 08 27 [2] 46 2b [2] 4a 21 [2] 5d 2a [2] 46 64 [2] 7b }

  condition:
    any of them
}