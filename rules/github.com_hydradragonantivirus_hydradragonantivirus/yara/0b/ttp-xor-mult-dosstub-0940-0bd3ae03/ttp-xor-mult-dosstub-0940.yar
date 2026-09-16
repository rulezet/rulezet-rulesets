rule TTP_XOR_MULT_DOSStub_0940 {
  strings:
    $key_0940 = { 5d 28 [2] 29 30 [2] 6e 32 [2] 29 23 [2] 67 2f [2] 6b 25 [2] 7c 2e [2] 67 60 [2] 5a }

  condition:
    any of them
}