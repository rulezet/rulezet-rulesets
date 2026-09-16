rule TTP_XOR_MULT_DOSStub_08c9 {
  strings:
    $key_08c9 = { 5c a1 [2] 28 b9 [2] 6f bb [2] 28 aa [2] 66 a6 [2] 6a ac [2] 7d a7 [2] 66 e9 [2] 5b }

  condition:
    any of them
}