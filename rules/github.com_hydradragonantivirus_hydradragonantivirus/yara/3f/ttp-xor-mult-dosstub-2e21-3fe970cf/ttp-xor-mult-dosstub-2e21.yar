rule TTP_XOR_MULT_DOSStub_2e21 {
  strings:
    $key_2e21 = { 7a 49 [2] 0e 51 [2] 49 53 [2] 0e 42 [2] 40 4e [2] 4c 44 [2] 5b 4f [2] 40 01 [2] 7d }

  condition:
    any of them
}