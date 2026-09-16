rule TTP_XOR_MULT_DOSStub_bfde {
  strings:
    $key_bfde = { eb b6 [2] 9f ae [2] d8 ac [2] 9f bd [2] d1 b1 [2] dd bb [2] ca b0 [2] d1 fe [2] ec }

  condition:
    any of them
}