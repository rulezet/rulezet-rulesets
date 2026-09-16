rule TTP_XOR_MULT_DOSStub_2e60 {
  strings:
    $key_2e60 = { 7a 08 [2] 0e 10 [2] 49 12 [2] 0e 03 [2] 40 0f [2] 4c 05 [2] 5b 0e [2] 40 40 [2] 7d }

  condition:
    any of them
}