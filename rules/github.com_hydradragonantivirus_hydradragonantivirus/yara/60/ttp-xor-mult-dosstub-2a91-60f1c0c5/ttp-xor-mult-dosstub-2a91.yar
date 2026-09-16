rule TTP_XOR_MULT_DOSStub_2a91 {
  strings:
    $key_2a91 = { 7e f9 [2] 0a e1 [2] 4d e3 [2] 0a f2 [2] 44 fe [2] 48 f4 [2] 5f ff [2] 44 b1 [2] 79 }

  condition:
    any of them
}