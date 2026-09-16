rule TTP_XOR_MULT_DOSStub_5acd {
  strings:
    $key_5acd = { 0e a5 [2] 7a bd [2] 3d bf [2] 7a ae [2] 34 a2 [2] 38 a8 [2] 2f a3 [2] 34 ed [2] 09 }

  condition:
    any of them
}