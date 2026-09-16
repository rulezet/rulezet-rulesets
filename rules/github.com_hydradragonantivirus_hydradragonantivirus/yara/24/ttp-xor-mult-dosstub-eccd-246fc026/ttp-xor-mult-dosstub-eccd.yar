rule TTP_XOR_MULT_DOSStub_eccd {
  strings:
    $key_eccd = { b8 a5 [2] cc bd [2] 8b bf [2] cc ae [2] 82 a2 [2] 8e a8 [2] 99 a3 [2] 82 ed [2] bf }

  condition:
    any of them
}