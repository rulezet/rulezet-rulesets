rule TTP_XOR_MULT_DOSStub_6ecb {
  strings:
    $key_6ecb = { 3a a3 [2] 4e bb [2] 09 b9 [2] 4e a8 [2] 00 a4 [2] 0c ae [2] 1b a5 [2] 00 eb [2] 3d }

  condition:
    any of them
}