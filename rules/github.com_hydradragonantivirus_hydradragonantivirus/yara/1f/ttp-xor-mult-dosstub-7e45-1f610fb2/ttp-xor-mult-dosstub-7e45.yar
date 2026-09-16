rule TTP_XOR_MULT_DOSStub_7e45 {
  strings:
    $key_7e45 = { 2a 2d [2] 5e 35 [2] 19 37 [2] 5e 26 [2] 10 2a [2] 1c 20 [2] 0b 2b [2] 10 65 [2] 2d }

  condition:
    any of them
}