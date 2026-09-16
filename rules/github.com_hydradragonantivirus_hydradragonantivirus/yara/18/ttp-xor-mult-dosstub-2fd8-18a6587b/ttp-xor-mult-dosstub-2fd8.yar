rule TTP_XOR_MULT_DOSStub_2fd8 {
  strings:
    $key_2fd8 = { 7b b0 [2] 0f a8 [2] 48 aa [2] 0f bb [2] 41 b7 [2] 4d bd [2] 5a b6 [2] 41 f8 [2] 7c }

  condition:
    any of them
}