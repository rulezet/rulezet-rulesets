rule TTP_XOR_MULT_DOSStub_3cde {
  strings:
    $key_3cde = { 68 b6 [2] 1c ae [2] 5b ac [2] 1c bd [2] 52 b1 [2] 5e bb [2] 49 b0 [2] 52 fe [2] 6f }

  condition:
    any of them
}