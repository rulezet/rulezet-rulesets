rule TTP_XOR_MULT_DOSStub_be03 {
  strings:
    $key_be03 = { ea 6b [2] 9e 73 [2] d9 71 [2] 9e 60 [2] d0 6c [2] dc 66 [2] cb 6d [2] d0 23 [2] ed }

  condition:
    any of them
}