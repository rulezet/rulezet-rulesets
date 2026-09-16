rule TTP_XOR_MULT_DOSStub_169c {
  strings:
    $key_169c = { 42 f4 [2] 36 ec [2] 71 ee [2] 36 ff [2] 78 f3 [2] 74 f9 [2] 63 f2 [2] 78 bc [2] 45 }

  condition:
    any of them
}