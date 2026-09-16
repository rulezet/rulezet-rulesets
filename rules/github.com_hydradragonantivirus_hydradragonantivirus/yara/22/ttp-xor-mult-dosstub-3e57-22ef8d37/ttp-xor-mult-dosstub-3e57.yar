rule TTP_XOR_MULT_DOSStub_3e57 {
  strings:
    $key_3e57 = { 6a 3f [2] 1e 27 [2] 59 25 [2] 1e 34 [2] 50 38 [2] 5c 32 [2] 4b 39 [2] 50 77 [2] 6d }

  condition:
    any of them
}