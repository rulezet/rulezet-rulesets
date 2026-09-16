rule TTP_XOR_MULT_DOSStub_fede {
  strings:
    $key_fede = { aa b6 [2] de ae [2] 99 ac [2] de bd [2] 90 b1 [2] 9c bb [2] 8b b0 [2] 90 fe [2] ad }

  condition:
    any of them
}