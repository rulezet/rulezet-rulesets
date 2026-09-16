rule TTP_XOR_MULT_DOSStub_be5d {
  strings:
    $key_be5d = { ea 35 [2] 9e 2d [2] d9 2f [2] 9e 3e [2] d0 32 [2] dc 38 [2] cb 33 [2] d0 7d [2] ed }

  condition:
    any of them
}