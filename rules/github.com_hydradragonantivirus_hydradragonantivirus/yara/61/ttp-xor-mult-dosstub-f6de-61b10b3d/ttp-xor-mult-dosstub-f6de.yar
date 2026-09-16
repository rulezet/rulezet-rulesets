rule TTP_XOR_MULT_DOSStub_f6de {
  strings:
    $key_f6de = { a2 b6 [2] d6 ae [2] 91 ac [2] d6 bd [2] 98 b1 [2] 94 bb [2] 83 b0 [2] 98 fe [2] a5 }

  condition:
    any of them
}