rule TTP_XOR_MULT_DOSStub_3976 {
  strings:
    $key_3976 = { 6d 1e [2] 19 06 [2] 5e 04 [2] 19 15 [2] 57 19 [2] 5b 13 [2] 4c 18 [2] 57 56 [2] 6a }

  condition:
    any of them
}