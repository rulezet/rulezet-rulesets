rule TTP_XOR_MULT_DOSStub_be77 {
  strings:
    $key_be77 = { ea 1f [2] 9e 07 [2] d9 05 [2] 9e 14 [2] d0 18 [2] dc 12 [2] cb 19 [2] d0 57 [2] ed }

  condition:
    any of them
}