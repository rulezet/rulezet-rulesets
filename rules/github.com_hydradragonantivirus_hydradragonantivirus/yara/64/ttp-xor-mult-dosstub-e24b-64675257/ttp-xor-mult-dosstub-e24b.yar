rule TTP_XOR_MULT_DOSStub_e24b {
  strings:
    $key_e24b = { b6 23 [2] c2 3b [2] 85 39 [2] c2 28 [2] 8c 24 [2] 80 2e [2] 97 25 [2] 8c 6b [2] b1 }

  condition:
    any of them
}