rule TTP_XOR_MULT_DOSStub_009c {
  strings:
    $key_009c = { 54 f4 [2] 20 ec [2] 67 ee [2] 20 ff [2] 6e f3 [2] 62 f9 [2] 75 f2 [2] 6e bc [2] 53 }

  condition:
    any of them
}