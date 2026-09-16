rule TTP_XOR_MULT_DOSStub_5dde {
  strings:
    $key_5dde = { 09 b6 [2] 7d ae [2] 3a ac [2] 7d bd [2] 33 b1 [2] 3f bb [2] 28 b0 [2] 33 fe [2] 0e }

  condition:
    any of them
}