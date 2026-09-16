rule TTP_XOR_MULT_DOSStub_be22 {
  strings:
    $key_be22 = { ea 4a [2] 9e 52 [2] d9 50 [2] 9e 41 [2] d0 4d [2] dc 47 [2] cb 4c [2] d0 02 [2] ed }

  condition:
    any of them
}