rule TTP_XOR_MULT_DOSStub_b71b {
  strings:
    $key_b71b = { e3 73 [2] 97 6b [2] d0 69 [2] 97 78 [2] d9 74 [2] d5 7e [2] c2 75 [2] d9 3b [2] e4 }

  condition:
    any of them
}