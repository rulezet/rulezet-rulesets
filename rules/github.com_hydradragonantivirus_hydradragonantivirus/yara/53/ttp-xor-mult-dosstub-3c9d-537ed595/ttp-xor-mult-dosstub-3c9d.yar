rule TTP_XOR_MULT_DOSStub_3c9d {
  strings:
    $key_3c9d = { 68 f5 [2] 1c ed [2] 5b ef [2] 1c fe [2] 52 f2 [2] 5e f8 [2] 49 f3 [2] 52 bd [2] 6f }

  condition:
    any of them
}