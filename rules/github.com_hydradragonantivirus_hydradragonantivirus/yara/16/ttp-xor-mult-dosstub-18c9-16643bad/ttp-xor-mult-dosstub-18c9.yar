rule TTP_XOR_MULT_DOSStub_18c9 {
  strings:
    $key_18c9 = { 4c a1 [2] 38 b9 [2] 7f bb [2] 38 aa [2] 76 a6 [2] 7a ac [2] 6d a7 [2] 76 e9 [2] 4b }

  condition:
    any of them
}