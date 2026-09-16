rule TTP_XOR_MULT_DOSStub_34e0 {
  strings:
    $key_34e0 = { 60 88 [2] 14 90 [2] 53 92 [2] 14 83 [2] 5a 8f [2] 56 85 [2] 41 8e [2] 5a c0 [2] 67 }

  condition:
    any of them
}