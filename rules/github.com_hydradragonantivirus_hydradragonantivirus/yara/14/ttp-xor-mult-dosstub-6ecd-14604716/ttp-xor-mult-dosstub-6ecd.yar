rule TTP_XOR_MULT_DOSStub_6ecd {
  strings:
    $key_6ecd = { 3a a5 [2] 4e bd [2] 09 bf [2] 4e ae [2] 00 a2 [2] 0c a8 [2] 1b a3 [2] 00 ed [2] 3d }

  condition:
    any of them
}