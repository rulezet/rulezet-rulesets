rule TTP_XOR_MULT_DOSStub_7ae1 {
  strings:
    $key_7ae1 = { 2e 89 [2] 5a 91 [2] 1d 93 [2] 5a 82 [2] 14 8e [2] 18 84 [2] 0f 8f [2] 14 c1 [2] 29 }

  condition:
    any of them
}