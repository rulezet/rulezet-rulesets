rule TTP_XOR_MULT_DOSStub_7b74 {
  strings:
    $key_7b74 = { 2f 1c [2] 5b 04 [2] 1c 06 [2] 5b 17 [2] 15 1b [2] 19 11 [2] 0e 1a [2] 15 54 [2] 28 }

  condition:
    any of them
}