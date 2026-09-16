rule TTP_XOR_MULT_DOSStub_2e30 {
  strings:
    $key_2e30 = { 7a 58 [2] 0e 40 [2] 49 42 [2] 0e 53 [2] 40 5f [2] 4c 55 [2] 5b 5e [2] 40 10 [2] 7d }

  condition:
    any of them
}