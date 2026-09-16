rule TTP_XOR_MULT_DOSStub_ddab {
  strings:
    $key_ddab = { 89 c3 [2] fd db [2] ba d9 [2] fd c8 [2] b3 c4 [2] bf ce [2] a8 c5 [2] b3 8b [2] 8e }

  condition:
    any of them
}