rule TTP_XOR_MULT_DOSStub_3dce {
  strings:
    $key_3dce = { 69 a6 [2] 1d be [2] 5a bc [2] 1d ad [2] 53 a1 [2] 5f ab [2] 48 a0 [2] 53 ee [2] 6e }

  condition:
    any of them
}