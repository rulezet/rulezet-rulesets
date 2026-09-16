rule TTP_XOR_MULT_DOSStub_7cde {
  strings:
    $key_7cde = { 28 b6 [2] 5c ae [2] 1b ac [2] 5c bd [2] 12 b1 [2] 1e bb [2] 09 b0 [2] 12 fe [2] 2f }

  condition:
    any of them
}