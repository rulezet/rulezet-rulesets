rule TTP_XOR_MULT_DOSStub_35f0 {
  strings:
    $key_35f0 = { 61 98 [2] 15 80 [2] 52 82 [2] 15 93 [2] 5b 9f [2] 57 95 [2] 40 9e [2] 5b d0 [2] 66 }

  condition:
    any of them
}