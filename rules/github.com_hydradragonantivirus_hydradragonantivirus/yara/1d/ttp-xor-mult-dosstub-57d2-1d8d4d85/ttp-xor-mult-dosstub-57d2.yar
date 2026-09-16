rule TTP_XOR_MULT_DOSStub_57d2 {
  strings:
    $key_57d2 = { 03 ba [2] 77 a2 [2] 30 a0 [2] 77 b1 [2] 39 bd [2] 35 b7 [2] 22 bc [2] 39 f2 [2] 04 }

  condition:
    any of them
}