rule TTP_XOR_MULT_DOSStub_be78 {
  strings:
    $key_be78 = { ea 10 [2] 9e 08 [2] d9 0a [2] 9e 1b [2] d0 17 [2] dc 1d [2] cb 16 [2] d0 58 [2] ed }

  condition:
    any of them
}