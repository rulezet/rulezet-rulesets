rule TTP_XOR_MULT_DOSStub_be4e {
  strings:
    $key_be4e = { ea 26 [2] 9e 3e [2] d9 3c [2] 9e 2d [2] d0 21 [2] dc 2b [2] cb 20 [2] d0 6e [2] ed }

  condition:
    any of them
}