rule TTP_XOR_MULT_DOSStub_be7d {
  strings:
    $key_be7d = { ea 15 [2] 9e 0d [2] d9 0f [2] 9e 1e [2] d0 12 [2] dc 18 [2] cb 13 [2] d0 5d [2] ed }

  condition:
    any of them
}