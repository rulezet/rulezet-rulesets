rule TTP_XOR_MULT_DOSStub_6fd8 {
  strings:
    $key_6fd8 = { 3b b0 [2] 4f a8 [2] 08 aa [2] 4f bb [2] 01 b7 [2] 0d bd [2] 1a b6 [2] 01 f8 [2] 3c }

  condition:
    any of them
}