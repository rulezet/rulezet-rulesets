rule TTP_XOR_MULT_DOSStub_4a91 {
  strings:
    $key_4a91 = { 1e f9 [2] 6a e1 [2] 2d e3 [2] 6a f2 [2] 24 fe [2] 28 f4 [2] 3f ff [2] 24 b1 [2] 19 }

  condition:
    any of them
}