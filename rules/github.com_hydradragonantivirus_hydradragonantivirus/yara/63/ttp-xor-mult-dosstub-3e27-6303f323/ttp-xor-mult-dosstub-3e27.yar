rule TTP_XOR_MULT_DOSStub_3e27 {
  strings:
    $key_3e27 = { 6a 4f [2] 1e 57 [2] 59 55 [2] 1e 44 [2] 50 48 [2] 5c 42 [2] 4b 49 [2] 50 07 [2] 6d }

  condition:
    any of them
}