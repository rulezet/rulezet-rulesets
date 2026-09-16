rule TTP_XOR_MULT_DOSStub_2557 {
  strings:
    $key_2557 = { 71 3f [2] 05 27 [2] 42 25 [2] 05 34 [2] 4b 38 [2] 47 32 [2] 50 39 [2] 4b 77 [2] 76 }

  condition:
    any of them
}