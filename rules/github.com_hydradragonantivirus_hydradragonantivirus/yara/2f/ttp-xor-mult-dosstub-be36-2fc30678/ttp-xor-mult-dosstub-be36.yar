rule TTP_XOR_MULT_DOSStub_be36 {
  strings:
    $key_be36 = { ea 5e [2] 9e 46 [2] d9 44 [2] 9e 55 [2] d0 59 [2] dc 53 [2] cb 58 [2] d0 16 [2] ed }

  condition:
    any of them
}