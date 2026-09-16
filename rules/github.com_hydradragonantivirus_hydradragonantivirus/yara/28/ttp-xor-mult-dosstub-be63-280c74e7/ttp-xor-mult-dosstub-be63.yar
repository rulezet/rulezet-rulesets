rule TTP_XOR_MULT_DOSStub_be63 {
  strings:
    $key_be63 = { ea 0b [2] 9e 13 [2] d9 11 [2] 9e 00 [2] d0 0c [2] dc 06 [2] cb 0d [2] d0 43 [2] ed }

  condition:
    any of them
}