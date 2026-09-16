rule TTP_XOR_MULT_DOSStub_619a {
  strings:
    $key_619a = { 35 f2 [2] 41 ea [2] 06 e8 [2] 41 f9 [2] 0f f5 [2] 03 ff [2] 14 f4 [2] 0f ba [2] 32 }

  condition:
    any of them
}