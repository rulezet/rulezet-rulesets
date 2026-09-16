rule TTP_XOR_MULT_DOSStub_be3b {
  strings:
    $key_be3b = { ea 53 [2] 9e 4b [2] d9 49 [2] 9e 58 [2] d0 54 [2] dc 5e [2] cb 55 [2] d0 1b [2] ed }

  condition:
    any of them
}