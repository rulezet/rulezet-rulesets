rule TTP_XOR_MULT_DOSStub_befc {
  strings:
    $key_befc = { ea 94 [2] 9e 8c [2] d9 8e [2] 9e 9f [2] d0 93 [2] dc 99 [2] cb 92 [2] d0 dc [2] ed }

  condition:
    any of them
}