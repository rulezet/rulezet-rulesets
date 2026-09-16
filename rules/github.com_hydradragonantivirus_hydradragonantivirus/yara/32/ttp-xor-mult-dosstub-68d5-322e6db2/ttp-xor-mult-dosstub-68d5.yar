rule TTP_XOR_MULT_DOSStub_68d5 {
  strings:
    $key_68d5 = { 3c bd [2] 48 a5 [2] 0f a7 [2] 48 b6 [2] 06 ba [2] 0a b0 [2] 1d bb [2] 06 f5 [2] 3b }

  condition:
    any of them
}