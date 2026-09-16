rule TTP_XOR_MULT_DOSStub_be79 {
  strings:
    $key_be79 = { ea 11 [2] 9e 09 [2] d9 0b [2] 9e 1a [2] d0 16 [2] dc 1c [2] cb 17 [2] d0 59 [2] ed }

  condition:
    any of them
}