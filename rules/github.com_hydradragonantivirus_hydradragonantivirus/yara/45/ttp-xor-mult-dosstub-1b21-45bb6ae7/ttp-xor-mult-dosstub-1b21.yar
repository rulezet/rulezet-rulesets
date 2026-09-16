rule TTP_XOR_MULT_DOSStub_1b21 {
  strings:
    $key_1b21 = { 4f 49 [2] 3b 51 [2] 7c 53 [2] 3b 42 [2] 75 4e [2] 79 44 [2] 6e 4f [2] 75 01 [2] 48 }

  condition:
    any of them
}