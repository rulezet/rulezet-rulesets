rule TTP_XOR_MULT_DOSStub_e258 {
  strings:
    $key_e258 = { b6 30 [2] c2 28 [2] 85 2a [2] c2 3b [2] 8c 37 [2] 80 3d [2] 97 36 [2] 8c 78 [2] b1 }

  condition:
    any of them
}