rule TTP_XOR_MULT_DOSStub_be7a {
  strings:
    $key_be7a = { ea 12 [2] 9e 0a [2] d9 08 [2] 9e 19 [2] d0 15 [2] dc 1f [2] cb 14 [2] d0 5a [2] ed }

  condition:
    any of them
}