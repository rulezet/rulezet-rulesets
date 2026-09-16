rule TTP_XOR_MULT_DOSStub_0ad0 {
  strings:
    $key_0ad0 = { 5e b8 [2] 2a a0 [2] 6d a2 [2] 2a b3 [2] 64 bf [2] 68 b5 [2] 7f be [2] 64 f0 [2] 59 }

  condition:
    any of them
}