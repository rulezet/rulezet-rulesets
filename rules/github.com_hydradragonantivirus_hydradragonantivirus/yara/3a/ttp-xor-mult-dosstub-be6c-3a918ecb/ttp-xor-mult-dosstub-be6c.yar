rule TTP_XOR_MULT_DOSStub_be6c {
  strings:
    $key_be6c = { ea 04 [2] 9e 1c [2] d9 1e [2] 9e 0f [2] d0 03 [2] dc 09 [2] cb 02 [2] d0 4c [2] ed }

  condition:
    any of them
}