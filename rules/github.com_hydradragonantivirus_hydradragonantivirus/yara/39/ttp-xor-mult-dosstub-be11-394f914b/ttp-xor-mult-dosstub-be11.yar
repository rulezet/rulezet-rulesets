rule TTP_XOR_MULT_DOSStub_be11 {
  strings:
    $key_be11 = { ea 79 [2] 9e 61 [2] d9 63 [2] 9e 72 [2] d0 7e [2] dc 74 [2] cb 7f [2] d0 31 [2] ed }

  condition:
    any of them
}