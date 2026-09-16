rule TTP_XOR_MULT_DOSStub_7b50 {
  strings:
    $key_7b50 = { 2f 38 [2] 5b 20 [2] 1c 22 [2] 5b 33 [2] 15 3f [2] 19 35 [2] 0e 3e [2] 15 70 [2] 28 }

  condition:
    any of them
}