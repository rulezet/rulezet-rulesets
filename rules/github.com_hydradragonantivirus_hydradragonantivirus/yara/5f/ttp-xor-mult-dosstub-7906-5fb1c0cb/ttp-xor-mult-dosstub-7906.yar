rule TTP_XOR_MULT_DOSStub_7906 {
  strings:
    $key_7906 = { 2d 6e [2] 59 76 [2] 1e 74 [2] 59 65 [2] 17 69 [2] 1b 63 [2] 0c 68 [2] 17 26 [2] 2a }

  condition:
    any of them
}