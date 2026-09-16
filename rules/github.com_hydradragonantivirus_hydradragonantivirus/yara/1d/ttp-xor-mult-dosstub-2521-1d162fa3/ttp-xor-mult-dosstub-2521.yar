rule TTP_XOR_MULT_DOSStub_2521 {
  strings:
    $key_2521 = { 71 49 [2] 05 51 [2] 42 53 [2] 05 42 [2] 4b 4e [2] 47 44 [2] 50 4f [2] 4b 01 [2] 76 }

  condition:
    any of them
}