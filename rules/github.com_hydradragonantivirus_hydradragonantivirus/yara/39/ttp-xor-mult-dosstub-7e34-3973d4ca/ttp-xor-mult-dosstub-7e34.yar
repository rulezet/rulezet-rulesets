rule TTP_XOR_MULT_DOSStub_7e34 {
  strings:
    $key_7e34 = { 2a 5c [2] 5e 44 [2] 19 46 [2] 5e 57 [2] 10 5b [2] 1c 51 [2] 0b 5a [2] 10 14 [2] 2d }

  condition:
    any of them
}