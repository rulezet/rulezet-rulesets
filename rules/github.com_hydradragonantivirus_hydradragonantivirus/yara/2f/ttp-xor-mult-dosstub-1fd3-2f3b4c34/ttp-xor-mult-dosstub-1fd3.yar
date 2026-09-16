rule TTP_XOR_MULT_DOSStub_1fd3 {
  strings:
    $key_1fd3 = { 4b bb [2] 3f a3 [2] 78 a1 [2] 3f b0 [2] 71 bc [2] 7d b6 [2] 6a bd [2] 71 f3 [2] 4c }

  condition:
    any of them
}