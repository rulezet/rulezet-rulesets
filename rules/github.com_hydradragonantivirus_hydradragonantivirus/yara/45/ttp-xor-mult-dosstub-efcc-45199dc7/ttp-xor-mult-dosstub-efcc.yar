rule TTP_XOR_MULT_DOSStub_efcc {
  strings:
    $key_efcc = { bb a4 [2] cf bc [2] 88 be [2] cf af [2] 81 a3 [2] 8d a9 [2] 9a a2 [2] 81 ec [2] bc }

  condition:
    any of them
}