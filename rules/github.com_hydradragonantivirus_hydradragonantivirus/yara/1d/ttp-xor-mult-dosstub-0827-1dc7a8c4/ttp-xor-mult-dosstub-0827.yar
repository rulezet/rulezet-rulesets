rule TTP_XOR_MULT_DOSStub_0827 {
  strings:
    $key_0827 = { 5c 4f [2] 28 57 [2] 6f 55 [2] 28 44 [2] 66 48 [2] 6a 42 [2] 7d 49 [2] 66 07 [2] 5b }

  condition:
    any of them
}