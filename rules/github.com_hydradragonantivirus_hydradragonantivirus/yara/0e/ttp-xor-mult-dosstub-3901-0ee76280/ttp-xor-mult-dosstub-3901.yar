rule TTP_XOR_MULT_DOSStub_3901 {
  strings:
    $key_3901 = { 6d 69 [2] 19 71 [2] 5e 73 [2] 19 62 [2] 57 6e [2] 5b 64 [2] 4c 6f [2] 57 21 [2] 6a }

  condition:
    any of them
}