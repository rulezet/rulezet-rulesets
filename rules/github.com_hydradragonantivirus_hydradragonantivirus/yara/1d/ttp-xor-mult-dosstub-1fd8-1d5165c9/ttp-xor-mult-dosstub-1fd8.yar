rule TTP_XOR_MULT_DOSStub_1fd8 {
  strings:
    $key_1fd8 = { 4b b0 [2] 3f a8 [2] 78 aa [2] 3f bb [2] 71 b7 [2] 7d bd [2] 6a b6 [2] 71 f8 [2] 4c }

  condition:
    any of them
}