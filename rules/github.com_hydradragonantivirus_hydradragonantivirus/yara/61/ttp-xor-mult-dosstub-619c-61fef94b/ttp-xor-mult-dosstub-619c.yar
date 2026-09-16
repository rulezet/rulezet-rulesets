rule TTP_XOR_MULT_DOSStub_619c {
  strings:
    $key_619c = { 35 f4 [2] 41 ec [2] 06 ee [2] 41 ff [2] 0f f3 [2] 03 f9 [2] 14 f2 [2] 0f bc [2] 32 }

  condition:
    any of them
}