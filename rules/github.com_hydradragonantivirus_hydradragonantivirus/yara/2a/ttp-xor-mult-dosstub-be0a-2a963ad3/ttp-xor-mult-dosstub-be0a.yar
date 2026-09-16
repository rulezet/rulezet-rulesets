rule TTP_XOR_MULT_DOSStub_be0a {
  strings:
    $key_be0a = { ea 62 [2] 9e 7a [2] d9 78 [2] 9e 69 [2] d0 65 [2] dc 6f [2] cb 64 [2] d0 2a [2] ed }

  condition:
    any of them
}