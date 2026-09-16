rule TTP_XOR_MULT_DOSStub_1ecb {
  strings:
    $key_1ecb = { 4a a3 [2] 3e bb [2] 79 b9 [2] 3e a8 [2] 70 a4 [2] 7c ae [2] 6b a5 [2] 70 eb [2] 4d }

  condition:
    any of them
}