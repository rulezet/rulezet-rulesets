rule TTP_XOR_MULT_DOSStub_7e78 {
  strings:
    $key_7e78 = { 2a 10 [2] 5e 08 [2] 19 0a [2] 5e 1b [2] 10 17 [2] 1c 1d [2] 0b 16 [2] 10 58 [2] 2d }

  condition:
    any of them
}