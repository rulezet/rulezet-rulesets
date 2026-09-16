rule TTP_XOR_MULT_DOSStub_be4c {
  strings:
    $key_be4c = { ea 24 [2] 9e 3c [2] d9 3e [2] 9e 2f [2] d0 23 [2] dc 29 [2] cb 22 [2] d0 6c [2] ed }

  condition:
    any of them
}