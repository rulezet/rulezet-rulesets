rule TTP_XOR_MULT_DOSStub_be61 {
  strings:
    $key_be61 = { ea 09 [2] 9e 11 [2] d9 13 [2] 9e 02 [2] d0 0e [2] dc 04 [2] cb 0f [2] d0 41 [2] ed }

  condition:
    any of them
}