rule TTP_XOR_MULT_DOSStub_be28 {
  strings:
    $key_be28 = { ea 40 [2] 9e 58 [2] d9 5a [2] 9e 4b [2] d0 47 [2] dc 4d [2] cb 46 [2] d0 08 [2] ed }

  condition:
    any of them
}