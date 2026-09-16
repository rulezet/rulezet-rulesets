rule TTP_XOR_MULT_DOSStub_5fd8 {
  strings:
    $key_5fd8 = { 0b b0 [2] 7f a8 [2] 38 aa [2] 7f bb [2] 31 b7 [2] 3d bd [2] 2a b6 [2] 31 f8 [2] 0c }

  condition:
    any of them
}