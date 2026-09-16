rule TTP_XOR_MULT_DOSStub_be6b {
  strings:
    $key_be6b = { ea 03 [2] 9e 1b [2] d9 19 [2] 9e 08 [2] d0 04 [2] dc 0e [2] cb 05 [2] d0 4b [2] ed }

  condition:
    any of them
}