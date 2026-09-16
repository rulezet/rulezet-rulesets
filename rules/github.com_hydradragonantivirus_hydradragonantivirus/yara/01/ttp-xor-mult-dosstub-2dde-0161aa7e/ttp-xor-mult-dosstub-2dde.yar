rule TTP_XOR_MULT_DOSStub_2dde {
  strings:
    $key_2dde = { 79 b6 [2] 0d ae [2] 4a ac [2] 0d bd [2] 43 b1 [2] 4f bb [2] 58 b0 [2] 43 fe [2] 7e }

  condition:
    any of them
}