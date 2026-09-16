rule TTP_XOR_MULT_DOSStub_61d2 {
  strings:
    $key_61d2 = { 35 ba [2] 41 a2 [2] 06 a0 [2] 41 b1 [2] 0f bd [2] 03 b7 [2] 14 bc [2] 0f f2 [2] 32 }

  condition:
    any of them
}