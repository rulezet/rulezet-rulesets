rule TTP_XOR_MULT_DOSStub_be2c {
  strings:
    $key_be2c = { ea 44 [2] 9e 5c [2] d9 5e [2] 9e 4f [2] d0 43 [2] dc 49 [2] cb 42 [2] d0 0c [2] ed }

  condition:
    any of them
}