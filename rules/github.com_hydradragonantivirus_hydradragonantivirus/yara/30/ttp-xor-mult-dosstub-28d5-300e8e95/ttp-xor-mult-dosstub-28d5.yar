rule TTP_XOR_MULT_DOSStub_28d5 {
  strings:
    $key_28d5 = { 7c bd [2] 08 a5 [2] 4f a7 [2] 08 b6 [2] 46 ba [2] 4a b0 [2] 5d bb [2] 46 f5 [2] 7b }

  condition:
    any of them
}