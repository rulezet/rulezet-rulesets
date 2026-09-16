rule TTP_XOR_MULT_DOSStub_0b78 {
  strings:
    $key_0b78 = { 5f 10 [2] 2b 08 [2] 6c 0a [2] 2b 1b [2] 65 17 [2] 69 1d [2] 7e 16 [2] 65 58 [2] 58 }

  condition:
    any of them
}