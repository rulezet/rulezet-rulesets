rule TTP_XOR_MULT_DOSStub_4fde {
  strings:
    $key_4fde = { 1b b6 [2] 6f ae [2] 28 ac [2] 6f bd [2] 21 b1 [2] 2d bb [2] 3a b0 [2] 21 fe [2] 1c }

  condition:
    any of them
}