rule TTP_XOR_MULT_DOSStub_befb {
  strings:
    $key_befb = { ea 93 [2] 9e 8b [2] d9 89 [2] 9e 98 [2] d0 94 [2] dc 9e [2] cb 95 [2] d0 db [2] ed }

  condition:
    any of them
}