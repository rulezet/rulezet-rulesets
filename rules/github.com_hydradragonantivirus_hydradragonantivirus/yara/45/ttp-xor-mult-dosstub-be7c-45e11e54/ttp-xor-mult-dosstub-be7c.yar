rule TTP_XOR_MULT_DOSStub_be7c {
  strings:
    $key_be7c = { ea 14 [2] 9e 0c [2] d9 0e [2] 9e 1f [2] d0 13 [2] dc 19 [2] cb 12 [2] d0 5c [2] ed }

  condition:
    any of them
}