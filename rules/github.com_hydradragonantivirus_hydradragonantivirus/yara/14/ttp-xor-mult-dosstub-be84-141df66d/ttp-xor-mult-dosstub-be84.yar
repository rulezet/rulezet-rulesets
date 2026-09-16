rule TTP_XOR_MULT_DOSStub_be84 {
  strings:
    $key_be84 = { ea ec [2] 9e f4 [2] d9 f6 [2] 9e e7 [2] d0 eb [2] dc e1 [2] cb ea [2] d0 a4 [2] ed }

  condition:
    any of them
}