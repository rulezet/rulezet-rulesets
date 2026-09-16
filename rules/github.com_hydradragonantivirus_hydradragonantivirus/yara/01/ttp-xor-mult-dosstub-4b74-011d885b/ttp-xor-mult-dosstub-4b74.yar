rule TTP_XOR_MULT_DOSStub_4b74 {
  strings:
    $key_4b74 = { 1f 1c [2] 6b 04 [2] 2c 06 [2] 6b 17 [2] 25 1b [2] 29 11 [2] 3e 1a [2] 25 54 [2] 18 }

  condition:
    any of them
}