rule TTP_XOR_MULT_DOSStub_e7e0 {
  strings:
    $key_e7e0 = { b3 88 [2] c7 90 [2] 80 92 [2] c7 83 [2] 89 8f [2] 85 85 [2] 92 8e [2] 89 c0 [2] b4 }

  condition:
    any of them
}