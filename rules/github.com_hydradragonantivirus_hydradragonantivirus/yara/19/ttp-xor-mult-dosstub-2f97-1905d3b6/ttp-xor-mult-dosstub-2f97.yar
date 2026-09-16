rule TTP_XOR_MULT_DOSStub_2f97 {
  strings:
    $key_2f97 = { 7b ff [2] 0f e7 [2] 48 e5 [2] 0f f4 [2] 41 f8 [2] 4d f2 [2] 5a f9 [2] 41 b7 [2] 7c }

  condition:
    any of them
}