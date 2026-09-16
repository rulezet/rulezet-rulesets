rule TTP_XOR_MULT_DOSStub_0b65 {
  strings:
    $key_0b65 = { 5f 0d [2] 2b 15 [2] 6c 17 [2] 2b 06 [2] 65 0a [2] 69 00 [2] 7e 0b [2] 65 45 [2] 58 }

  condition:
    any of them
}