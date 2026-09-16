rule TTP_XOR_MULT_DOSStub_be75 {
  strings:
    $key_be75 = { ea 1d [2] 9e 05 [2] d9 07 [2] 9e 16 [2] d0 1a [2] dc 10 [2] cb 1b [2] d0 55 [2] ed }

  condition:
    any of them
}