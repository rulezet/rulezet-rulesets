rule TTP_XOR_MULT_DOSStub_3906 {
  strings:
    $key_3906 = { 6d 6e [2] 19 76 [2] 5e 74 [2] 19 65 [2] 57 69 [2] 5b 63 [2] 4c 68 [2] 57 26 [2] 6a }

  condition:
    any of them
}