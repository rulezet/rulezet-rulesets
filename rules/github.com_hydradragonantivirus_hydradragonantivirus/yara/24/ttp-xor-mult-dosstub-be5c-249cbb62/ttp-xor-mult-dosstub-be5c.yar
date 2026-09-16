rule TTP_XOR_MULT_DOSStub_be5c {
  strings:
    $key_be5c = { ea 34 [2] 9e 2c [2] d9 2e [2] 9e 3f [2] d0 33 [2] dc 39 [2] cb 32 [2] d0 7c [2] ed }

  condition:
    any of them
}