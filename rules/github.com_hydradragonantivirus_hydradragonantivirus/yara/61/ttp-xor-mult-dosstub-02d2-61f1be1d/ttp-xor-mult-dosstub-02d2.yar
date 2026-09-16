rule TTP_XOR_MULT_DOSStub_02d2 {
  strings:
    $key_02d2 = { 56 ba [2] 22 a2 [2] 65 a0 [2] 22 b1 [2] 6c bd [2] 60 b7 [2] 77 bc [2] 6c f2 [2] 51 }

  condition:
    any of them
}