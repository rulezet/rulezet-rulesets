rule TTP_XOR_MULT_DOSStub_6fde {
  strings:
    $key_6fde = { 3b b6 [2] 4f ae [2] 08 ac [2] 4f bd [2] 01 b1 [2] 0d bb [2] 1a b0 [2] 01 fe [2] 3c }

  condition:
    any of them
}