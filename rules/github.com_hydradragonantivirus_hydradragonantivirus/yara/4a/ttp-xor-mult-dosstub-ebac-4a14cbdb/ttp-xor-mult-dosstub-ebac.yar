rule TTP_XOR_MULT_DOSStub_ebac {
  strings:
    $key_ebac = { bf c4 [2] cb dc [2] 8c de [2] cb cf [2] 85 c3 [2] 89 c9 [2] 9e c2 [2] 85 8c [2] b8 }

  condition:
    any of them
}