rule TTP_XOR_MULT_DOSStub_4fd8 {
  strings:
    $key_4fd8 = { 1b b0 [2] 6f a8 [2] 28 aa [2] 6f bb [2] 21 b7 [2] 2d bd [2] 3a b6 [2] 21 f8 [2] 1c }

  condition:
    any of them
}