rule TTP_XOR_MULT_DOSStub_be0f {
  strings:
    $key_be0f = { ea 67 [2] 9e 7f [2] d9 7d [2] 9e 6c [2] d0 60 [2] dc 6a [2] cb 61 [2] d0 2f [2] ed }

  condition:
    any of them
}