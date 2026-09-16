rule TTP_XOR_MULT_DOSStub_2e11 {
  strings:
    $key_2e11 = { 7a 79 [2] 0e 61 [2] 49 63 [2] 0e 72 [2] 40 7e [2] 4c 74 [2] 5b 7f [2] 40 31 [2] 7d }

  condition:
    any of them
}