rule TTP_XOR_MULT_DOSStub_7df0 {
  strings:
    $key_7df0 = { 29 98 [2] 5d 80 [2] 1a 82 [2] 5d 93 [2] 13 9f [2] 1f 95 [2] 08 9e [2] 13 d0 [2] 2e }

  condition:
    any of them
}