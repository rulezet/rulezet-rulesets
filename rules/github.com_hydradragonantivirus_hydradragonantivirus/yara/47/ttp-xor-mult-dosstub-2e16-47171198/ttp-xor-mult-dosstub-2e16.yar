rule TTP_XOR_MULT_DOSStub_2e16 {
  strings:
    $key_2e16 = { 7a 7e [2] 0e 66 [2] 49 64 [2] 0e 75 [2] 40 79 [2] 4c 73 [2] 5b 78 [2] 40 36 [2] 7d }

  condition:
    any of them
}