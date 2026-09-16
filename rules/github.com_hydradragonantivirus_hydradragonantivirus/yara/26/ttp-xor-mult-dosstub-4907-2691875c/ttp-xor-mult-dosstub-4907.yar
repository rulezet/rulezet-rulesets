rule TTP_XOR_MULT_DOSStub_4907 {
  strings:
    $key_4907 = { 1d 6f [2] 69 77 [2] 2e 75 [2] 69 64 [2] 27 68 [2] 2b 62 [2] 3c 69 [2] 27 27 [2] 1a }

  condition:
    any of them
}