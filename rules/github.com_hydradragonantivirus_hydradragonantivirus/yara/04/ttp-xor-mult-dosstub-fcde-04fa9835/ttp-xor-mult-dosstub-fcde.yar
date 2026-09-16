rule TTP_XOR_MULT_DOSStub_fcde {
  strings:
    $key_fcde = { a8 b6 [2] dc ae [2] 9b ac [2] dc bd [2] 92 b1 [2] 9e bb [2] 89 b0 [2] 92 fe [2] af }

  condition:
    any of them
}