rule TTP_XOR_MULT_DOSStub_3e47 {
  strings:
    $key_3e47 = { 6a 2f [2] 1e 37 [2] 59 35 [2] 1e 24 [2] 50 28 [2] 5c 22 [2] 4b 29 [2] 50 67 [2] 6d }

  condition:
    any of them
}