rule TTP_XOR_MULT_DOSStub_0be1 {
  strings:
    $key_0be1 = { 5f 89 [2] 2b 91 [2] 6c 93 [2] 2b 82 [2] 65 8e [2] 69 84 [2] 7e 8f [2] 65 c1 [2] 58 }

  condition:
    any of them
}