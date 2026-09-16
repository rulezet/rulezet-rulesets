rule TTP_XOR_MULT_DOSStub_be7e {
  strings:
    $key_be7e = { ea 16 [2] 9e 0e [2] d9 0c [2] 9e 1d [2] d0 11 [2] dc 1b [2] cb 10 [2] d0 5e [2] ed }

  condition:
    any of them
}