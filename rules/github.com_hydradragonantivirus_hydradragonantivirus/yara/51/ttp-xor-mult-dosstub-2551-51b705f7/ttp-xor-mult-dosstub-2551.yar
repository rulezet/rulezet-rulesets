rule TTP_XOR_MULT_DOSStub_2551 {
  strings:
    $key_2551 = { 71 39 [2] 05 21 [2] 42 23 [2] 05 32 [2] 4b 3e [2] 47 34 [2] 50 3f [2] 4b 71 [2] 76 }

  condition:
    any of them
}