rule TTP_XOR_MULT_DOSStub_1eab {
  strings:
    $key_1eab = { 4a c3 [2] 3e db [2] 79 d9 [2] 3e c8 [2] 70 c4 [2] 7c ce [2] 6b c5 [2] 70 8b [2] 4d }

  condition:
    any of them
}