rule TTP_XOR_MULT_DOSStub_be47 {
  strings:
    $key_be47 = { ea 2f [2] 9e 37 [2] d9 35 [2] 9e 24 [2] d0 28 [2] dc 22 [2] cb 29 [2] d0 67 [2] ed }

  condition:
    any of them
}