rule TTP_XOR_MULT_DOSStub_3b21 {
  strings:
    $key_3b21 = { 6f 49 [2] 1b 51 [2] 5c 53 [2] 1b 42 [2] 55 4e [2] 59 44 [2] 4e 4f [2] 55 01 [2] 68 }

  condition:
    any of them
}