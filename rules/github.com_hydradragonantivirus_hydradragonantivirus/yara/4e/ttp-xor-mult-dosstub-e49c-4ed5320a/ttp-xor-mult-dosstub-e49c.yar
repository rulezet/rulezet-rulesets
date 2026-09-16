rule TTP_XOR_MULT_DOSStub_e49c {
  strings:
    $key_e49c = { b0 f4 [2] c4 ec [2] 83 ee [2] c4 ff [2] 8a f3 [2] 86 f9 [2] 91 f2 [2] 8a bc [2] b7 }

  condition:
    any of them
}