rule TTP_XOR_MULT_DOSStub_7e49 {
  strings:
    $key_7e49 = { 2a 21 [2] 5e 39 [2] 19 3b [2] 5e 2a [2] 10 26 [2] 1c 2c [2] 0b 27 [2] 10 69 [2] 2d }

  condition:
    any of them
}