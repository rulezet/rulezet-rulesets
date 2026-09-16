rule TTP_XOR_MULT_DOSStub_e39c {
  strings:
    $key_e39c = { b7 f4 [2] c3 ec [2] 84 ee [2] c3 ff [2] 8d f3 [2] 81 f9 [2] 96 f2 [2] 8d bc [2] b0 }

  condition:
    any of them
}