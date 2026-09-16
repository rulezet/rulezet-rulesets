rule TTP_XOR_MULT_DOSStub_3c40 {
  strings:
    $key_3c40 = { 68 28 [2] 1c 30 [2] 5b 32 [2] 1c 23 [2] 52 2f [2] 5e 25 [2] 49 2e [2] 52 60 [2] 6f }

  condition:
    any of them
}