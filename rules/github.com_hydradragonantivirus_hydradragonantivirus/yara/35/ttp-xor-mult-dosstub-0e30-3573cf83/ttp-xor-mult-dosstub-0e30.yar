rule TTP_XOR_MULT_DOSStub_0e30 {
  strings:
    $key_0e30 = { 5a 58 [2] 2e 40 [2] 69 42 [2] 2e 53 [2] 60 5f [2] 6c 55 [2] 7b 5e [2] 60 10 [2] 5d }

  condition:
    any of them
}