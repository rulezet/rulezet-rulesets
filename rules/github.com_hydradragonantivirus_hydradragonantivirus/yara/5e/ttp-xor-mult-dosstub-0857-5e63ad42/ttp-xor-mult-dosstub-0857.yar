rule TTP_XOR_MULT_DOSStub_0857 {
  strings:
    $key_0857 = { 5c 3f [2] 28 27 [2] 6f 25 [2] 28 34 [2] 66 38 [2] 6a 32 [2] 7d 39 [2] 66 77 [2] 5b }

  condition:
    any of them
}