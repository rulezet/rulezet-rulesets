rule TTP_XOR_MULT_DOSStub_30e1 {
  strings:
    $key_30e1 = { 64 89 [2] 10 91 [2] 57 93 [2] 10 82 [2] 5e 8e [2] 52 84 [2] 45 8f [2] 5e c1 [2] 63 }

  condition:
    any of them
}