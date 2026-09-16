rule TTP_XOR_MULT_DOSStub_be74 {
  strings:
    $key_be74 = { ea 1c [2] 9e 04 [2] d9 06 [2] 9e 17 [2] d0 1b [2] dc 11 [2] cb 1a [2] d0 54 [2] ed }

  condition:
    any of them
}