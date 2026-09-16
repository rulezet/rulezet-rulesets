rule TTP_XOR_MULT_DOSStub_be17 {
  strings:
    $key_be17 = { ea 7f [2] 9e 67 [2] d9 65 [2] 9e 74 [2] d0 78 [2] dc 72 [2] cb 79 [2] d0 37 [2] ed }

  condition:
    any of them
}