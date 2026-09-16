rule TTP_XOR_MULT_DOSStub_1b74 {
  strings:
    $key_1b74 = { 4f 1c [2] 3b 04 [2] 7c 06 [2] 3b 17 [2] 75 1b [2] 79 11 [2] 6e 1a [2] 75 54 [2] 48 }

  condition:
    any of them
}