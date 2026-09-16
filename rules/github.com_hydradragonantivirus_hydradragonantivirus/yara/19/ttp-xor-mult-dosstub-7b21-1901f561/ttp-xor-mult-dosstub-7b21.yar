rule TTP_XOR_MULT_DOSStub_7b21 {
  strings:
    $key_7b21 = { 2f 49 [2] 5b 51 [2] 1c 53 [2] 5b 42 [2] 15 4e [2] 19 44 [2] 0e 4f [2] 15 01 [2] 28 }

  condition:
    any of them
}