rule TTP_XOR_MULT_DOSStub_3ecd {
  strings:
    $key_3ecd = { 6a a5 [2] 1e bd [2] 59 bf [2] 1e ae [2] 50 a2 [2] 5c a8 [2] 4b a3 [2] 50 ed [2] 6d }

  condition:
    any of them
}