rule TTP_XOR_MULT_DOSStub_0074 {
  strings:
    $key_0074 = { 54 1c [2] 20 04 [2] 67 06 [2] 20 17 [2] 6e 1b [2] 62 11 [2] 75 1a [2] 6e 54 [2] 53 }

  condition:
    any of them
}