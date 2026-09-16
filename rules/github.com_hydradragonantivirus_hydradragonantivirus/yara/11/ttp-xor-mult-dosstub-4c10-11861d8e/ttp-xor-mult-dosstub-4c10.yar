rule TTP_XOR_MULT_DOSStub_4c10 {
  strings:
    $key_4c10 = { 18 78 [2] 6c 60 [2] 2b 62 [2] 6c 73 [2] 22 7f [2] 2e 75 [2] 39 7e [2] 22 30 [2] 1f }

  condition:
    any of them
}