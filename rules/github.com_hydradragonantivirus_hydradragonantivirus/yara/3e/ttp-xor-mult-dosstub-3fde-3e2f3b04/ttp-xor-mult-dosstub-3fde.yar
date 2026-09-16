rule TTP_XOR_MULT_DOSStub_3fde {
  strings:
    $key_3fde = { 6b b6 [2] 1f ae [2] 58 ac [2] 1f bd [2] 51 b1 [2] 5d bb [2] 4a b0 [2] 51 fe [2] 6c }

  condition:
    any of them
}