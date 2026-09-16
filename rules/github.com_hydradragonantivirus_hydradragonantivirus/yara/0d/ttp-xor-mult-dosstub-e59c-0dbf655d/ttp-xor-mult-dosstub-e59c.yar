rule TTP_XOR_MULT_DOSStub_e59c {
  strings:
    $key_e59c = { b1 f4 [2] c5 ec [2] 82 ee [2] c5 ff [2] 8b f3 [2] 87 f9 [2] 90 f2 [2] 8b bc [2] b6 }

  condition:
    any of them
}