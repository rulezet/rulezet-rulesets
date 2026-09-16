rule TTP_XOR_MULT_DOSStub_3b78 {
  strings:
    $key_3b78 = { 6f 10 [2] 1b 08 [2] 5c 0a [2] 1b 1b [2] 55 17 [2] 59 1d [2] 4e 16 [2] 55 58 [2] 68 }

  condition:
    any of them
}