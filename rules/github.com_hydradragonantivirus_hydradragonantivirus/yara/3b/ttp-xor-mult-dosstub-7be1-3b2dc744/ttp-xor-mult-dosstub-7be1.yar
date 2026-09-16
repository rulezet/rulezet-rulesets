rule TTP_XOR_MULT_DOSStub_7be1 {
  strings:
    $key_7be1 = { 2f 89 [2] 5b 91 [2] 1c 93 [2] 5b 82 [2] 15 8e [2] 19 84 [2] 0e 8f [2] 15 c1 [2] 28 }

  condition:
    any of them
}