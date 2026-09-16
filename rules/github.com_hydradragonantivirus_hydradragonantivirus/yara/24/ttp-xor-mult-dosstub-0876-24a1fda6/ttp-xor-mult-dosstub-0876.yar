rule TTP_XOR_MULT_DOSStub_0876 {
  strings:
    $key_0876 = { 5c 1e [2] 28 06 [2] 6f 04 [2] 28 15 [2] 66 19 [2] 6a 13 [2] 7d 18 [2] 66 56 [2] 5b }

  condition:
    any of them
}