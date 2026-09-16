rule TTP_XOR_MULT_DOSStub_139c {
  strings:
    $key_139c = { 47 f4 [2] 33 ec [2] 74 ee [2] 33 ff [2] 7d f3 [2] 71 f9 [2] 66 f2 [2] 7d bc [2] 40 }

  condition:
    any of them
}