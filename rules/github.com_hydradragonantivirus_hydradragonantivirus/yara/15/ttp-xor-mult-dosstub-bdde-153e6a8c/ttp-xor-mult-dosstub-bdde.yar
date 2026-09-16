rule TTP_XOR_MULT_DOSStub_bdde {
  strings:
    $key_bdde = { e9 b6 [2] 9d ae [2] da ac [2] 9d bd [2] d3 b1 [2] df bb [2] c8 b0 [2] d3 fe [2] ee }

  condition:
    any of them
}