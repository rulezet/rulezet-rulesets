rule TTP_XOR_MULT_DOSStub_2074 {
  strings:
    $key_2074 = { 74 1c [2] 00 04 [2] 47 06 [2] 00 17 [2] 4e 1b [2] 42 11 [2] 55 1a [2] 4e 54 [2] 73 }

  condition:
    any of them
}