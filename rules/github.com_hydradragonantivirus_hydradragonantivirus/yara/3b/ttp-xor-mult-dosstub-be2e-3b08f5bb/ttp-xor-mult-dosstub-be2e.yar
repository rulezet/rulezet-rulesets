rule TTP_XOR_MULT_DOSStub_be2e {
  strings:
    $key_be2e = { ea 46 [2] 9e 5e [2] d9 5c [2] 9e 4d [2] d0 41 [2] dc 4b [2] cb 40 [2] d0 0e [2] ed }

  condition:
    any of them
}