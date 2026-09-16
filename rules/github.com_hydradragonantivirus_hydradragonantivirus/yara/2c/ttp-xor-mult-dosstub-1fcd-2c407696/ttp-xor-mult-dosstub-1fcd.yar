rule TTP_XOR_MULT_DOSStub_1fcd {
  strings:
    $key_1fcd = { 4b a5 [2] 3f bd [2] 78 bf [2] 3f ae [2] 71 a2 [2] 7d a8 [2] 6a a3 [2] 71 ed [2] 4c }

  condition:
    any of them
}