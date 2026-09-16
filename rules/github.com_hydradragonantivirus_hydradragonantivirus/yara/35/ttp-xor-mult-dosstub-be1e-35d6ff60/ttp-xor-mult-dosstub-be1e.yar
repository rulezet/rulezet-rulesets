rule TTP_XOR_MULT_DOSStub_be1e {
  strings:
    $key_be1e = { ea 76 [2] 9e 6e [2] d9 6c [2] 9e 7d [2] d0 71 [2] dc 7b [2] cb 70 [2] d0 3e [2] ed }

  condition:
    any of them
}