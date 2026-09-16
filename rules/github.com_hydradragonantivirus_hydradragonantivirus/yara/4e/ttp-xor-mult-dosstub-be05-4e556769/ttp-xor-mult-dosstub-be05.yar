rule TTP_XOR_MULT_DOSStub_be05 {
  strings:
    $key_be05 = { ea 6d [2] 9e 75 [2] d9 77 [2] 9e 66 [2] d0 6a [2] dc 60 [2] cb 6b [2] d0 25 [2] ed }

  condition:
    any of them
}