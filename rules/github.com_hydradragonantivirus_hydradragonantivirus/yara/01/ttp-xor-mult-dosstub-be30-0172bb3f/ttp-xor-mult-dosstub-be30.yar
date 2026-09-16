rule TTP_XOR_MULT_DOSStub_be30 {
  strings:
    $key_be30 = { ea 58 [2] 9e 40 [2] d9 42 [2] 9e 53 [2] d0 5f [2] dc 55 [2] cb 5e [2] d0 10 [2] ed }

  condition:
    any of them
}