rule TTP_XOR_MULT_DOSStub_7c9d {
  strings:
    $key_7c9d = { 28 f5 [2] 5c ed [2] 1b ef [2] 5c fe [2] 12 f2 [2] 1e f8 [2] 09 f3 [2] 12 bd [2] 2f }

  condition:
    any of them
}