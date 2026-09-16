rule TTP_XOR_MULT_DOSStub_7acd {
  strings:
    $key_7acd = { 2e a5 [2] 5a bd [2] 1d bf [2] 5a ae [2] 14 a2 [2] 18 a8 [2] 0f a3 [2] 14 ed [2] 29 }

  condition:
    any of them
}