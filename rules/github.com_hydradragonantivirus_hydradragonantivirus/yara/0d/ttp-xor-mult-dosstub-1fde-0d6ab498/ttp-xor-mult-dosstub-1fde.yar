rule TTP_XOR_MULT_DOSStub_1fde {
  strings:
    $key_1fde = { 4b b6 [2] 3f ae [2] 78 ac [2] 3f bd [2] 71 b1 [2] 7d bb [2] 6a b0 [2] 71 fe [2] 4c }

  condition:
    any of them
}