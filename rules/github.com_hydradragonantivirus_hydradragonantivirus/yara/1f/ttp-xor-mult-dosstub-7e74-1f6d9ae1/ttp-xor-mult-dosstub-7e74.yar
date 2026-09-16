rule TTP_XOR_MULT_DOSStub_7e74 {
  strings:
    $key_7e74 = { 2a 1c [2] 5e 04 [2] 19 06 [2] 5e 17 [2] 10 1b [2] 1c 11 [2] 0b 1a [2] 10 54 [2] 2d }

  condition:
    any of them
}