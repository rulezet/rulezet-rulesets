rule TTP_XOR_MULT_DOSStub_be04 {
  strings:
    $key_be04 = { ea 6c [2] 9e 74 [2] d9 76 [2] 9e 67 [2] d0 6b [2] dc 61 [2] cb 6a [2] d0 24 [2] ed }

  condition:
    any of them
}