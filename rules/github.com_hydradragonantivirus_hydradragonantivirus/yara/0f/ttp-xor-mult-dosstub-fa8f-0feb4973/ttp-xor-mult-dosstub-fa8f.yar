rule TTP_XOR_MULT_DOSStub_fa8f {
  strings:
    $key_fa8f = { ae e7 [2] da ff [2] 9d fd [2] da ec [2] 94 e0 [2] 98 ea [2] 8f e1 [2] 94 af [2] a9 }

  condition:
    any of them
}