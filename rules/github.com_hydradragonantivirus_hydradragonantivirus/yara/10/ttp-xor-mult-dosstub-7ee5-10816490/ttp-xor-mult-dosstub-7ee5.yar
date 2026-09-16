rule TTP_XOR_MULT_DOSStub_7ee5 {
  strings:
    $key_7ee5 = { 2a 8d [2] 5e 95 [2] 19 97 [2] 5e 86 [2] 10 8a [2] 1c 80 [2] 0b 8b [2] 10 c5 [2] 2d }

  condition:
    any of them
}