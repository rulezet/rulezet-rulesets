rule TTP_XOR_MULT_DOSStub_7268 {
  strings:
    $key_7268 = { 26 00 [2] 52 18 [2] 15 1a [2] 52 0b [2] 1c 07 [2] 10 0d [2] 07 06 [2] 1c 48 [2] 21 }

  condition:
    any of them
}