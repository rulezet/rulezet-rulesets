rule TTP_XOR_MULT_DOSStub_be65 {
  strings:
    $key_be65 = { ea 0d [2] 9e 15 [2] d9 17 [2] 9e 06 [2] d0 0a [2] dc 00 [2] cb 0b [2] d0 45 [2] ed }

  condition:
    any of them
}