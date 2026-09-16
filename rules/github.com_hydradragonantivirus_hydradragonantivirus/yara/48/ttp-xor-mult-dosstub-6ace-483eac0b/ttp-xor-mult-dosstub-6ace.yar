rule TTP_XOR_MULT_DOSStub_6ace {
  strings:
    $key_6ace = { 3e a6 [2] 4a be [2] 0d bc [2] 4a ad [2] 04 a1 [2] 08 ab [2] 1f a0 [2] 04 ee [2] 39 }

  condition:
    any of them
}