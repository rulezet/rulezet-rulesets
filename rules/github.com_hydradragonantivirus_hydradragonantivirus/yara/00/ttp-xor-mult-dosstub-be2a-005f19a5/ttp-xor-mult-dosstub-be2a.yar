rule TTP_XOR_MULT_DOSStub_be2a {
  strings:
    $key_be2a = { ea 42 [2] 9e 5a [2] d9 58 [2] 9e 49 [2] d0 45 [2] dc 4f [2] cb 44 [2] d0 0a [2] ed }

  condition:
    any of them
}