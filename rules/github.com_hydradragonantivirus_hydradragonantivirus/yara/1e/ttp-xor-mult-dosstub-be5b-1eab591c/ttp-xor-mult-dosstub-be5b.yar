rule TTP_XOR_MULT_DOSStub_be5b {
  strings:
    $key_be5b = { ea 33 [2] 9e 2b [2] d9 29 [2] 9e 38 [2] d0 34 [2] dc 3e [2] cb 35 [2] d0 7b [2] ed }

  condition:
    any of them
}