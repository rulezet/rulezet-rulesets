rule TTP_XOR_MULT_DOSStub_7b78 {
  strings:
    $key_7b78 = { 2f 10 [2] 5b 08 [2] 1c 0a [2] 5b 1b [2] 15 17 [2] 19 1d [2] 0e 16 [2] 15 58 [2] 28 }

  condition:
    any of them
}