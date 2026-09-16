rule TTP_XOR_MULT_DOSStub_48de {
  strings:
    $key_48de = { 1c b6 [2] 68 ae [2] 2f ac [2] 68 bd [2] 26 b1 [2] 2a bb [2] 3d b0 [2] 26 fe [2] 1b }

  condition:
    any of them
}