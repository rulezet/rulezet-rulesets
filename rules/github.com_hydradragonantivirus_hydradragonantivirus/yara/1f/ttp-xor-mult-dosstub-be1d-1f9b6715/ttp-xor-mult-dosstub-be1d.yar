rule TTP_XOR_MULT_DOSStub_be1d {
  strings:
    $key_be1d = { ea 75 [2] 9e 6d [2] d9 6f [2] 9e 7e [2] d0 72 [2] dc 78 [2] cb 73 [2] d0 3d [2] ed }

  condition:
    any of them
}