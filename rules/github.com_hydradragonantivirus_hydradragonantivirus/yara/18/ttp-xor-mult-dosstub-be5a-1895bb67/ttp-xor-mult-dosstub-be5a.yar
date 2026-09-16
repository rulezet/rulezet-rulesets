rule TTP_XOR_MULT_DOSStub_be5a {
  strings:
    $key_be5a = { ea 32 [2] 9e 2a [2] d9 28 [2] 9e 39 [2] d0 35 [2] dc 3f [2] cb 34 [2] d0 7a [2] ed }

  condition:
    any of them
}