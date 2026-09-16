rule TTP_XOR_MULT_DOSStub_51d9 {
  strings:
    $key_51d9 = { 05 b1 [2] 71 a9 [2] 36 ab [2] 71 ba [2] 3f b6 [2] 33 bc [2] 24 b7 [2] 3f f9 [2] 02 }

  condition:
    any of them
}