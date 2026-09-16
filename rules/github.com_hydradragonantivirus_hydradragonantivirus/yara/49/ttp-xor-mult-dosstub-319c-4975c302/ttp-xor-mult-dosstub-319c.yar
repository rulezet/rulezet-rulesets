rule TTP_XOR_MULT_DOSStub_319c {
  strings:
    $key_319c = { 65 f4 [2] 11 ec [2] 56 ee [2] 11 ff [2] 5f f3 [2] 53 f9 [2] 44 f2 [2] 5f bc [2] 62 }

  condition:
    any of them
}