rule TTP_XOR_MULT_DOSStub_7e65 {
  strings:
    $key_7e65 = { 2a 0d [2] 5e 15 [2] 19 17 [2] 5e 06 [2] 10 0a [2] 1c 00 [2] 0b 0b [2] 10 45 [2] 2d }

  condition:
    any of them
}