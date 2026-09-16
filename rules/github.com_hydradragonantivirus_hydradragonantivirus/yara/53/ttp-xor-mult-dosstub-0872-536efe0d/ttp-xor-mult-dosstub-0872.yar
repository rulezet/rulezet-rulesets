rule TTP_XOR_MULT_DOSStub_0872 {
  strings:
    $key_0872 = { 5c 1a [2] 28 02 [2] 6f 00 [2] 28 11 [2] 66 1d [2] 6a 17 [2] 7d 1c [2] 66 52 [2] 5b }

  condition:
    any of them
}