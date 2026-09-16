rule TTP_XOR_MULT_DOSStub_718f {
  strings:
    $key_718f = { 25 e7 [2] 51 ff [2] 16 fd [2] 51 ec [2] 1f e0 [2] 13 ea [2] 04 e1 [2] 1f af [2] 22 }

  condition:
    any of them
}