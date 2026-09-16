rule TTP_XOR_MULT_DOSStub_34e6 {
  strings:
    $key_34e6 = { 60 8e [2] 14 96 [2] 53 94 [2] 14 85 [2] 5a 89 [2] 56 83 [2] 41 88 [2] 5a c6 [2] 67 }

  condition:
    any of them
}