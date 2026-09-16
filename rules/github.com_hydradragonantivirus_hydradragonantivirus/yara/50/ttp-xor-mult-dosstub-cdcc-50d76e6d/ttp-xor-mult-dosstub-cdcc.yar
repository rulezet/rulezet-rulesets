rule TTP_XOR_MULT_DOSStub_cdcc {
  strings:
    $key_cdcc = { 99 a4 [2] ed bc [2] aa be [2] ed af [2] a3 a3 [2] af a9 [2] b8 a2 [2] a3 ec [2] 9e }

  condition:
    any of them
}