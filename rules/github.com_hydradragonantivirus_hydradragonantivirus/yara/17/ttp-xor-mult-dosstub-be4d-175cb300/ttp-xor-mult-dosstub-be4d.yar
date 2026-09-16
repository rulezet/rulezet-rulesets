rule TTP_XOR_MULT_DOSStub_be4d {
  strings:
    $key_be4d = { ea 25 [2] 9e 3d [2] d9 3f [2] 9e 2e [2] d0 22 [2] dc 28 [2] cb 23 [2] d0 6d [2] ed }

  condition:
    any of them
}