rule TTP_XOR_MULT_DOSStub_7e57 {
  strings:
    $key_7e57 = { 2a 3f [2] 5e 27 [2] 19 25 [2] 5e 34 [2] 10 38 [2] 1c 32 [2] 0b 39 [2] 10 77 [2] 2d }

  condition:
    any of them
}