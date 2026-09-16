rule TTP_XOR_MULT_DOSStub_5e27 {
  strings:
    $key_5e27 = { 0a 4f [2] 7e 57 [2] 39 55 [2] 7e 44 [2] 30 48 [2] 3c 42 [2] 2b 49 [2] 30 07 [2] 0d }

  condition:
    any of them
}