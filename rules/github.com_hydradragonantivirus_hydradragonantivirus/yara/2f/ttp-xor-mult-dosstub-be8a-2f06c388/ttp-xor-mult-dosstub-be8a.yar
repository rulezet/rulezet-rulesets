rule TTP_XOR_MULT_DOSStub_be8a {
  strings:
    $key_be8a = { ea e2 [2] 9e fa [2] d9 f8 [2] 9e e9 [2] d0 e5 [2] dc ef [2] cb e4 [2] d0 aa [2] ed }

  condition:
    any of them
}