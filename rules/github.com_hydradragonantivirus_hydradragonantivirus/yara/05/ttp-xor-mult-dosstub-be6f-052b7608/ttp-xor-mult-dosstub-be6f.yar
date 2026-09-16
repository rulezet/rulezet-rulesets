rule TTP_XOR_MULT_DOSStub_be6f {
  strings:
    $key_be6f = { ea 07 [2] 9e 1f [2] d9 1d [2] 9e 0c [2] d0 00 [2] dc 0a [2] cb 01 [2] d0 4f [2] ed }

  condition:
    any of them
}