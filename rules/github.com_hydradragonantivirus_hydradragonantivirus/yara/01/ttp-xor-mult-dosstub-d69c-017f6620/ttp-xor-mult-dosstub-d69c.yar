rule TTP_XOR_MULT_DOSStub_d69c {
  strings:
    $key_d69c = { 82 f4 [2] f6 ec [2] b1 ee [2] f6 ff [2] b8 f3 [2] b4 f9 [2] a3 f2 [2] b8 bc [2] 85 }

  condition:
    any of them
}