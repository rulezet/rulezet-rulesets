rule TTP_XOR_MULT_DOSStub_6fcd {
  strings:
    $key_6fcd = { 3b a5 [2] 4f bd [2] 08 bf [2] 4f ae [2] 01 a2 [2] 0d a8 [2] 1a a3 [2] 01 ed [2] 3c }

  condition:
    any of them
}