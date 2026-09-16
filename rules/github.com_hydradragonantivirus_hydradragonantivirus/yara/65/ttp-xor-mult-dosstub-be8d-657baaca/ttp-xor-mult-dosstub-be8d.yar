rule TTP_XOR_MULT_DOSStub_be8d {
  strings:
    $key_be8d = { ea e5 [2] 9e fd [2] d9 ff [2] 9e ee [2] d0 e2 [2] dc e8 [2] cb e3 [2] d0 ad [2] ed }

  condition:
    any of them
}