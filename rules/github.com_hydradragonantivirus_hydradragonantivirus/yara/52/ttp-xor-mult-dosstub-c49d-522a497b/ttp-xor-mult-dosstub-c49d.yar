rule TTP_XOR_MULT_DOSStub_c49d {
  strings:
    $key_c49d = { 90 f5 [2] e4 ed [2] a3 ef [2] e4 fe [2] aa f2 [2] a6 f8 [2] b1 f3 [2] aa bd [2] 97 }

  condition:
    any of them
}