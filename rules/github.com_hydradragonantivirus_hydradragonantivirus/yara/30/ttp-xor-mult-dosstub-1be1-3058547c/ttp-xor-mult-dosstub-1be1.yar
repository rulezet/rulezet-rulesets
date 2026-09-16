rule TTP_XOR_MULT_DOSStub_1be1 {
  strings:
    $key_1be1 = { 4f 89 [2] 3b 91 [2] 7c 93 [2] 3b 82 [2] 75 8e [2] 79 84 [2] 6e 8f [2] 75 c1 [2] 48 }

  condition:
    any of them
}