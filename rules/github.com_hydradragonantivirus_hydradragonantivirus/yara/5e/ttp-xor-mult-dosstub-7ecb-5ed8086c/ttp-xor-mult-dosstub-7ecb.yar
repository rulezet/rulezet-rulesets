rule TTP_XOR_MULT_DOSStub_7ecb {
  strings:
    $key_7ecb = { 2a a3 [2] 5e bb [2] 19 b9 [2] 5e a8 [2] 10 a4 [2] 1c ae [2] 0b a5 [2] 10 eb [2] 2d }

  condition:
    any of them
}