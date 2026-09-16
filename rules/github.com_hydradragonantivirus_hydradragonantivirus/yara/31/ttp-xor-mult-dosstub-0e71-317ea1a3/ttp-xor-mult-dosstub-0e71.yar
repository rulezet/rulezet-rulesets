rule TTP_XOR_MULT_DOSStub_0e71 {
  strings:
    $key_0e71 = { 5a 19 [2] 2e 01 [2] 69 03 [2] 2e 12 [2] 60 1e [2] 6c 14 [2] 7b 1f [2] 60 51 [2] 5d }

  condition:
    any of them
}