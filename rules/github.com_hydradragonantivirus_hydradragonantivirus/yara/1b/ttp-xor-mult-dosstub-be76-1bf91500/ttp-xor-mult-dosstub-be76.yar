rule TTP_XOR_MULT_DOSStub_be76 {
  strings:
    $key_be76 = { ea 1e [2] 9e 06 [2] d9 04 [2] 9e 15 [2] d0 19 [2] dc 13 [2] cb 18 [2] d0 56 [2] ed }

  condition:
    any of them
}