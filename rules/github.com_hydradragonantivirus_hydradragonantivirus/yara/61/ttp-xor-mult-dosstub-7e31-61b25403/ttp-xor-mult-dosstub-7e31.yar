rule TTP_XOR_MULT_DOSStub_7e31 {
  strings:
    $key_7e31 = { 2a 59 [2] 5e 41 [2] 19 43 [2] 5e 52 [2] 10 5e [2] 1c 54 [2] 0b 5f [2] 10 11 [2] 2d }

  condition:
    any of them
}