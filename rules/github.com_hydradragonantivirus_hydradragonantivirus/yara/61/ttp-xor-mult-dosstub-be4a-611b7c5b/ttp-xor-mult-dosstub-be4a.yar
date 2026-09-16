rule TTP_XOR_MULT_DOSStub_be4a {
  strings:
    $key_be4a = { ea 22 [2] 9e 3a [2] d9 38 [2] 9e 29 [2] d0 25 [2] dc 2f [2] cb 24 [2] d0 6a [2] ed }

  condition:
    any of them
}