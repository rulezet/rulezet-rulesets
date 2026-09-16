rule TTP_XOR_MULT_DOSStub_fbab {
  strings:
    $key_fbab = { af c3 [2] db db [2] 9c d9 [2] db c8 [2] 95 c4 [2] 99 ce [2] 8e c5 [2] 95 8b [2] a8 }

  condition:
    any of them
}