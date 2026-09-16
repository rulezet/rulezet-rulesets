rule TTP_XOR_MULT_DOSStub_b703 {
  strings:
    $key_b703 = { e3 6b [2] 97 73 [2] d0 71 [2] 97 60 [2] d9 6c [2] d5 66 [2] c2 6d [2] d9 23 [2] e4 }

  condition:
    any of them
}