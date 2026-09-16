rule TTP_XOR_MULT_DOSStub_1e60 {
  strings:
    $key_1e60 = { 4a 08 [2] 3e 10 [2] 79 12 [2] 3e 03 [2] 70 0f [2] 7c 05 [2] 6b 0e [2] 70 40 [2] 4d }

  condition:
    any of them
}