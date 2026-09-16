rule TTP_XOR_MULT_DOSStub_0b28 {
  strings:
    $key_0b28 = { 5f 40 [2] 2b 58 [2] 6c 5a [2] 2b 4b [2] 65 47 [2] 69 4d [2] 7e 46 [2] 65 08 [2] 58 }

  condition:
    any of them
}