rule TTP_XOR_MULT_DOSStub_bbde {
  strings:
    $key_bbde = { ef b6 [2] 9b ae [2] dc ac [2] 9b bd [2] d5 b1 [2] d9 bb [2] ce b0 [2] d5 fe [2] e8 }

  condition:
    any of them
}