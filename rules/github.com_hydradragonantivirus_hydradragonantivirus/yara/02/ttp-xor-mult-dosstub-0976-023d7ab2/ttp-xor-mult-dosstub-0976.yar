rule TTP_XOR_MULT_DOSStub_0976 {
  strings:
    $key_0976 = { 5d 1e [2] 29 06 [2] 6e 04 [2] 29 15 [2] 67 19 [2] 6b 13 [2] 7c 18 [2] 67 56 [2] 5a }

  condition:
    any of them
}