rule TTP_XOR_MULT_DOSStub_ec9d {
  strings:
    $key_ec9d = { b8 f5 [2] cc ed [2] 8b ef [2] cc fe [2] 82 f2 [2] 8e f8 [2] 99 f3 [2] 82 bd [2] bf }

  condition:
    any of them
}