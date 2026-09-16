rule TTP_XOR_MULT_DOSStub_be93 {
  strings:
    $key_be93 = { ea fb [2] 9e e3 [2] d9 e1 [2] 9e f0 [2] d0 fc [2] dc f6 [2] cb fd [2] d0 b3 [2] ed }

  condition:
    any of them
}