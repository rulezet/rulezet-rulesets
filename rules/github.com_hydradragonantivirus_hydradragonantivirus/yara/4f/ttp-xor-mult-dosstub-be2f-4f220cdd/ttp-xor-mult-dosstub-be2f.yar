rule TTP_XOR_MULT_DOSStub_be2f {
  strings:
    $key_be2f = { ea 47 [2] 9e 5f [2] d9 5d [2] 9e 4c [2] d0 40 [2] dc 4a [2] cb 41 [2] d0 0f [2] ed }

  condition:
    any of them
}