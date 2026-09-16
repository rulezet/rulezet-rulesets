rule TTP_XOR_MULT_DOSStub_0e60 {
  strings:
    $key_0e60 = { 5a 08 [2] 2e 10 [2] 69 12 [2] 2e 03 [2] 60 0f [2] 6c 05 [2] 7b 0e [2] 60 40 [2] 5d }

  condition:
    any of them
}