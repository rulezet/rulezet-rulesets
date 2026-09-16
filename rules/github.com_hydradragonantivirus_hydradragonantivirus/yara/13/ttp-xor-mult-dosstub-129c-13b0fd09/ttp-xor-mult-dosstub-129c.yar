rule TTP_XOR_MULT_DOSStub_129c {
  strings:
    $key_129c = { 46 f4 [2] 32 ec [2] 75 ee [2] 32 ff [2] 7c f3 [2] 70 f9 [2] 67 f2 [2] 7c bc [2] 41 }

  condition:
    any of them
}