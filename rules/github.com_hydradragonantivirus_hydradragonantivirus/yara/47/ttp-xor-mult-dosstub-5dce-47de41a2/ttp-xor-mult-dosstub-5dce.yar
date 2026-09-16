rule TTP_XOR_MULT_DOSStub_5dce {
  strings:
    $key_5dce = { 09 a6 [2] 7d be [2] 3a bc [2] 7d ad [2] 33 a1 [2] 3f ab [2] 28 a0 [2] 33 ee [2] 0e }

  condition:
    any of them
}