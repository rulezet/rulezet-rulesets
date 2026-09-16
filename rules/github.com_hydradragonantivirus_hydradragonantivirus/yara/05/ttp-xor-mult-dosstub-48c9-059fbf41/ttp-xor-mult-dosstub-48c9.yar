rule TTP_XOR_MULT_DOSStub_48c9 {
  strings:
    $key_48c9 = { 1c a1 [2] 68 b9 [2] 2f bb [2] 68 aa [2] 26 a6 [2] 2a ac [2] 3d a7 [2] 26 e9 [2] 1b }

  condition:
    any of them
}