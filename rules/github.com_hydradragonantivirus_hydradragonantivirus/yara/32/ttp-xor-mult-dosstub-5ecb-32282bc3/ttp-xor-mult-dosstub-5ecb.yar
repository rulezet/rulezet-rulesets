rule TTP_XOR_MULT_DOSStub_5ecb {
  strings:
    $key_5ecb = { 0a a3 [2] 7e bb [2] 39 b9 [2] 7e a8 [2] 30 a4 [2] 3c ae [2] 2b a5 [2] 30 eb [2] 0d }

  condition:
    any of them
}