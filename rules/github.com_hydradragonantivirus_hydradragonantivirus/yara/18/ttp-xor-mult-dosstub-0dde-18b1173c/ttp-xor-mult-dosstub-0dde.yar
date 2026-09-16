rule TTP_XOR_MULT_DOSStub_0dde {
  strings:
    $key_0dde = { 59 b6 [2] 2d ae [2] 6a ac [2] 2d bd [2] 63 b1 [2] 6f bb [2] 78 b0 [2] 63 fe [2] 5e }

  condition:
    any of them
}