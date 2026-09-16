rule TTP_XOR_MULT_DOSStub_0b74 {
  strings:
    $key_0b74 = { 5f 1c [2] 2b 04 [2] 6c 06 [2] 2b 17 [2] 65 1b [2] 69 11 [2] 7e 1a [2] 65 54 [2] 58 }

  condition:
    any of them
}