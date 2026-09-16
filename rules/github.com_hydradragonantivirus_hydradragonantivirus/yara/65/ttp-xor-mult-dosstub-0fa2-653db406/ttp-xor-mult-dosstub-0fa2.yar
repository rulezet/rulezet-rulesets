rule TTP_XOR_MULT_DOSStub_0fa2 {
  strings:
    $key_0fa2 = { 5b ca [2] 2f d2 [2] 68 d0 [2] 2f c1 [2] 61 cd [2] 6d c7 [2] 7a cc [2] 61 82 [2] 5c }

  condition:
    any of them
}