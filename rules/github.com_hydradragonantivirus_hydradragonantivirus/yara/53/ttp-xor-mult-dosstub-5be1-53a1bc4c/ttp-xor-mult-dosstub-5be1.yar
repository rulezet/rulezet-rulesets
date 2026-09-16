rule TTP_XOR_MULT_DOSStub_5be1 {
  strings:
    $key_5be1 = { 0f 89 [2] 7b 91 [2] 3c 93 [2] 7b 82 [2] 35 8e [2] 39 84 [2] 2e 8f [2] 35 c1 [2] 08 }

  condition:
    any of them
}