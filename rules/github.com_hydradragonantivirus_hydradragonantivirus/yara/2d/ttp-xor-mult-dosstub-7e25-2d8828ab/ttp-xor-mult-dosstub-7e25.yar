rule TTP_XOR_MULT_DOSStub_7e25 {
  strings:
    $key_7e25 = { 2a 4d [2] 5e 55 [2] 19 57 [2] 5e 46 [2] 10 4a [2] 1c 40 [2] 0b 4b [2] 10 05 [2] 2d }

  condition:
    any of them
}