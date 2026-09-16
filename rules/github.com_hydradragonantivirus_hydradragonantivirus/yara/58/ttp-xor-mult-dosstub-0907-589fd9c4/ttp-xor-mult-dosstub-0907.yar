rule TTP_XOR_MULT_DOSStub_0907 {
  strings:
    $key_0907 = { 5d 6f [2] 29 77 [2] 6e 75 [2] 29 64 [2] 67 68 [2] 6b 62 [2] 7c 69 [2] 67 27 [2] 5a }

  condition:
    any of them
}