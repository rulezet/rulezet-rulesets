rule TTP_XOR_MULT_DOSStub_be3c {
  strings:
    $key_be3c = { ea 54 [2] 9e 4c [2] d9 4e [2] 9e 5f [2] d0 53 [2] dc 59 [2] cb 52 [2] d0 1c [2] ed }

  condition:
    any of them
}