rule TTP_XOR_MULT_DOSStub_08ca {
  strings:
    $key_08ca = { 5c a2 [2] 28 ba [2] 6f b8 [2] 28 a9 [2] 66 a5 [2] 6a af [2] 7d a4 [2] 66 ea [2] 5b }

  condition:
    any of them
}