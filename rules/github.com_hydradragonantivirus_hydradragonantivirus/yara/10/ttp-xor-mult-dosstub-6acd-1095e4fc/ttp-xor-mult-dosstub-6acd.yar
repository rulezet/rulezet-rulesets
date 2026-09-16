rule TTP_XOR_MULT_DOSStub_6acd {
  strings:
    $key_6acd = { 3e a5 [2] 4a bd [2] 0d bf [2] 4a ae [2] 04 a2 [2] 08 a8 [2] 1f a3 [2] 04 ed [2] 39 }

  condition:
    any of them
}