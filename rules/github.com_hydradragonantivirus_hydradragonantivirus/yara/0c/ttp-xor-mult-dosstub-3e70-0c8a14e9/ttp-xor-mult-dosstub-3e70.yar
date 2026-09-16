rule TTP_XOR_MULT_DOSStub_3e70 {
  strings:
    $key_3e70 = { 6a 18 [2] 1e 00 [2] 59 02 [2] 1e 13 [2] 50 1f [2] 5c 15 [2] 4b 1e [2] 50 50 [2] 6d }

  condition:
    any of them
}