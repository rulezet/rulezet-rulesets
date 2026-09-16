rule TTP_XOR_MULT_DOSStub_1fd2 {
  strings:
    $key_1fd2 = { 4b ba [2] 3f a2 [2] 78 a0 [2] 3f b1 [2] 71 bd [2] 7d b7 [2] 6a bc [2] 71 f2 [2] 4c }

  condition:
    any of them
}