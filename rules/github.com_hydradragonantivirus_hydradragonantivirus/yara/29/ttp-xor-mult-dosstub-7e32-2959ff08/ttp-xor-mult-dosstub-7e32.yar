rule TTP_XOR_MULT_DOSStub_7e32 {
  strings:
    $key_7e32 = { 2a 5a [2] 5e 42 [2] 19 40 [2] 5e 51 [2] 10 5d [2] 1c 57 [2] 0b 5c [2] 10 12 [2] 2d }

  condition:
    any of them
}