rule TTP_XOR_MULT_DOSStub_4dde {
  strings:
    $key_4dde = { 19 b6 [2] 6d ae [2] 2a ac [2] 6d bd [2] 23 b1 [2] 2f bb [2] 38 b0 [2] 23 fe [2] 1e }

  condition:
    any of them
}