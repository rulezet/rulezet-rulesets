rule TTP_XOR_MULT_DOSStub_4c71 {
  strings:
    $key_4c71 = { 18 19 [2] 6c 01 [2] 2b 03 [2] 6c 12 [2] 22 1e [2] 2e 14 [2] 39 1f [2] 22 51 [2] 1f }

  condition:
    any of them
}