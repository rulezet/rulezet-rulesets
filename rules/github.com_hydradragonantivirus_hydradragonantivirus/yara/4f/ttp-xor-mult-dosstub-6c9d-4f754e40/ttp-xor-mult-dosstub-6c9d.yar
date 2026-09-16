rule TTP_XOR_MULT_DOSStub_6c9d {
  strings:
    $key_6c9d = { 38 f5 [2] 4c ed [2] 0b ef [2] 4c fe [2] 02 f2 [2] 0e f8 [2] 19 f3 [2] 02 bd [2] 3f }

  condition:
    any of them
}