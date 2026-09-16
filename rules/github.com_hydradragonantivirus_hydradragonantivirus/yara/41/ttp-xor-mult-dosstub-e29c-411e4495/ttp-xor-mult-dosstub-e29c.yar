rule TTP_XOR_MULT_DOSStub_e29c {
  strings:
    $key_e29c = { b6 f4 [2] c2 ec [2] 85 ee [2] c2 ff [2] 8c f3 [2] 80 f9 [2] 97 f2 [2] 8c bc [2] b1 }

  condition:
    any of them
}