rule TTP_XOR_MULT_DOSStub_be89 {
  strings:
    $key_be89 = { ea e1 [2] 9e f9 [2] d9 fb [2] 9e ea [2] d0 e6 [2] dc ec [2] cb e7 [2] d0 a9 [2] ed }

  condition:
    any of them
}