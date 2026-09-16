rule TTP_XOR_MULT_DOSStub_7ee7 {
  strings:
    $key_7ee7 = { 2a 8f [2] 5e 97 [2] 19 95 [2] 5e 84 [2] 10 88 [2] 1c 82 [2] 0b 89 [2] 10 c7 [2] 2d }

  condition:
    any of them
}