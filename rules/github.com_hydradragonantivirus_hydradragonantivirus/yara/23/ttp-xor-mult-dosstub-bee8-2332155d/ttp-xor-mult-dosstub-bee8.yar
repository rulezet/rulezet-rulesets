rule TTP_XOR_MULT_DOSStub_bee8 {
  strings:
    $key_bee8 = { ea 80 [2] 9e 98 [2] d9 9a [2] 9e 8b [2] d0 87 [2] dc 8d [2] cb 86 [2] d0 c8 [2] ed }

  condition:
    any of them
}