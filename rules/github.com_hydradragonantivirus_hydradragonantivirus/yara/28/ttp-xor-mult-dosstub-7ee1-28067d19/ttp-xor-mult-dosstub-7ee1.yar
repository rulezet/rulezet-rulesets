rule TTP_XOR_MULT_DOSStub_7ee1 {
  strings:
    $key_7ee1 = { 2a 89 [2] 5e 91 [2] 19 93 [2] 5e 82 [2] 10 8e [2] 1c 84 [2] 0b 8f [2] 10 c1 [2] 2d }

  condition:
    any of them
}