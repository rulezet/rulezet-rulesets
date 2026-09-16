rule TTP_XOR_MULT_DOSStub_be35 {
  strings:
    $key_be35 = { ea 5d [2] 9e 45 [2] d9 47 [2] 9e 56 [2] d0 5a [2] dc 50 [2] cb 5b [2] d0 15 [2] ed }

  condition:
    any of them
}